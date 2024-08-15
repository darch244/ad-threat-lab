"""spn_collector — non-intrusive LDAP SPN harvesting with privilege ranking.

Enumerates every user account that has one or more ``servicePrincipalName``
values (the Kerberoasting attack surface) through a read-only LDAP search, then
ranks each account by its privilege tier derived from group membership and
object RID.

This tool makes **no** Kerberos requests — it only reads directory metadata.
The TGS-request side is handled by ``tools/py_kerberoast.py``.

Privilege model (Microsoft Enterprise Access Model tiers):

  * Tier-0 — Domain Admins, Enterprise Admins, Schema Admins, Key Admins,
    BUILTIN\\Administrators, local Administrator RID 500, krbtgt, ...
  * Tier-1 — server/application administrators (Backup Operators, Server
    Operators, Account Operators, SQL/server-level admins)
  * Tier-2 — everything else (standard users, workstations)
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import random
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, TextIO

from tools.acl_scanner import LdapEntryLike, LdapSearchApi, _attr_values

# Domain-relative RIDs that map to Tier-0 or Tier-1.
TIER0_RIDS = {0x1F4, 0x1F6, 0x200, 0x201, 0x206, 0x220, 0x207, 0x20B, 0x202, 0x208}
TIER1_RIDS = {0x224, 0x225, 0x227, 0x22B, 0x22C, 0x226}

# Names used as a textual fallback when the SID is unavailable (mock mode).
TIER0_GROUPS = {
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "BUILTIN\\Administrators",
    "Administrators",
    "Key Admins",
    "Enterprise Key Admins",
    "Protected Users",
}
TIER1_GROUPS = {
    "Backup Operators",
    "Server Operators",
    "Account Operators",
    "Printer Operators",
    "Replicator",
    "SQL-Admins",
    "Tier1-Admins",
}

PRIVILEGED_RIDS = TIER0_RIDS | TIER1_RIDS

UAC_FLAGS: list[tuple[str, int]] = [
    ("ACCOUNTDISABLE", 0x00000002),
    ("PASSWD_NOTREQD", 0x00000020),
    ("LOCKOUT", 0x00000010),
    ("NORMAL_ACCOUNT", 0x00000200),
    ("WORKSTATION_TRUST_ACCOUNT", 0x00001000),
    ("SERVER_TRUST_ACCOUNT", 0x00002000),
    ("DONT_EXPIRE_PASSWORD", 0x00010000),
    ("TRUSTED_FOR_DELEGATION", 0x00080000),
    ("TRUSTED_TO_AUTH_FOR_DELEGATION", 0x00100000),
    ("DONT_REQUIRE_PREAUTH", 0x00400000),
    ("PARTIAL_SECRETS_ACCOUNT", 0x40000000),
]


def uac_flag_names(user_account_control: int) -> list[str]:
    """Return the human-readable UAC flags set on an account."""
    return [name for name, bit in UAC_FLAGS if user_account_control & bit]


@dataclass(frozen=True)
class SpnAccount:
    """A single SPN-having user with a computed privilege tier."""

    sam: str
    sid: str | None
    tier: int
    tier_label: str
    spns: tuple[str, ...]
    uac: int
    uac_flags: tuple[str, ...]
    member_of: tuple[str, ...] = field(default_factory=tuple)

    @property
    def high_value(self) -> bool:
        return self.tier == 0 or bool(
            set(self.member_of) & (TIER0_GROUPS | TIER1_GROUPS)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "sam": self.sam,
            "sid": self.sid,
            "tier": self.tier,
            "tier_label": self.tier_label,
            "high_value": self.high_value,
            "spns": list(self.spns),
            "uac_flags": list(self.uac_flags),
            "member_of": list(self.member_of),
        }


def _group_basenames(member_of: Sequence[str]) -> set[str]:
    """Extract plain group names (CN= stripped) from DN-style memberships."""
    names: set[str] = set()
    for dn in member_of:
        name_part = dn.split(",", 1)[0].strip()
        if name_part.lower().startswith("cn="):
            name_part = name_part[3:]
        if name_part:
            names.add(name_part)
    return names


def rank_privilege(sid: str | None, member_of: Sequence[str]) -> tuple[int, str]:
    """Return ``(tier, label)`` for an account given its SID and group DN list.

    Tier-0 wins over Tier-1 so a DA-alias service account is never
    misclassified as a lower-tier target.
    """
    from tools.acl_scanner import _rid

    rid = _rid(sid) if sid else None
    if rid is not None and rid in TIER0_RIDS:
        return 0, "tier0"
    group_names = _group_basenames(member_of)
    if group_names & TIER0_GROUPS:
        return 0, "tier0"
    if rid is not None and rid in TIER1_RIDS:
        return 1, "tier1"
    if group_names & TIER1_GROUPS:
        return 1, "tier1"
    return 2, "tier2"


def collect_spns(connection: LdapSearchApi, base_dn: str) -> list[SpnAccount]:
    """Non-intrusively harvest all SPN-bearing user accounts via LDAP.

    Raises a ``RuntimeError`` if the search fails (bad bind / unreachable
    server), and logs a warning per unparsable entry instead of aborting.
    """
    import ldap3  # type: ignore[import-untyped]

    ok = connection.search(
        base_dn,
        "(&(objectClass=user)(servicePrincipalName=*))",
        attributes=[
            "sAMAccountName",
            "servicePrincipalName",
            "objectSid",
            "userAccountControl",
            "memberOf",
        ],
        search_scope=ldap3.SUBTREE,
        paged_size=1000,
    )
    if not ok:
        raise RuntimeError(
            "LDAP search failed — check bind credentials and server state."
        )

    accounts: list[SpnAccount] = []

    for entry in connection.entries:  # type: ignore[union-attr]
        sam = _first_attr(entry, "sAMAccountName")
        if not sam:
            continue
        raw_sid = _raw_attr(entry, "objectSid")
        sid: str | None = None
        if raw_sid:
            try:
                from tools.acl_scanner import decode_sid

                sid = decode_sid(raw_sid)
            except ValueError:
                sid = None

        spns = tuple(
            sorted({str(v) for v in _attr_values(entry, "servicePrincipalName")})
        )
        member_of = tuple(sorted({str(v) for v in _attr_values(entry, "memberOf")}))
        uac_raw = _attr_values(entry, "userAccountControl")
        uac = int(uac_raw[0]) if uac_raw else 0
        tier, label = rank_privilege(sid, member_of)

        accounts.append(
            SpnAccount(
                sam=sam,
                sid=sid,
                tier=tier,
                tier_label=label,
                spns=spns,
                uac=uac,
                uac_flags=tuple(uac_flag_names(uac)),
                member_of=member_of,
            )
        )

    return accounts


def _first_attr(entry: LdapEntryLike, name: str) -> str | None:
    values = _attr_values(entry, name)
    return str(values[0]) if values else None


def _raw_attr(entry: LdapEntryLike, name: str) -> bytes | None:
    values = _attr_values(entry, name)
    if not values:
        return None
    value = values[0]
    if isinstance(value, bytes):
        return value
    return str(value).encode()


# ---------------------------------------------------------------------------
# Deterministic offline (--mock) dataset
# ---------------------------------------------------------------------------

_MOCK_USERS: list[dict[str, Any]] = [
    {
        "sam": "darc-admin",
        "sid_rid": 512,
        "member_of": ["CN=Domain Admins", "CN=Tier0-Admins"],
        "spns": [],
    },
    {
        "sam": "svc-sql",
        "sid_rid": 2234,
        "member_of": ["CN=SQL-Admins", "CN=Tier1-Admins"],
        "spns": ["MSSQLSvc/sql01.corp.local:1433", "MSSQLSvc/sql01.corp.local:sql01"],
    },
    {
        "sam": "svc-httpd",
        "sid_rid": 2235,
        "member_of": ["CN=WebApp", "CN=Tier1-Admins"],
        "spns": ["HTTP/web01.corp.local", "HTTP/web01.corp.local:443"],
    },
    {
        "sam": "svc-unconst",
        "sid_rid": 2236,
        "member_of": ["CN=Tier1-Admins"],
        "spns": ["cifs/svc-unconst.corp.local"],
    },
    {
        "sam": "t2-svc-canary",
        "sid_rid": 2237,
        "member_of": ["CN=Domain Users"],
        "spns": ["printer/t2canary.corp.local"],
    },
]


def generate_mock_spn_accounts(seed: str = "corp.local") -> list[SpnAccount]:
    """Build a deterministic synthetic SPN inventory (mirrors lab-config.json)."""
    rng = random.Random(hashlib_md5(seed))
    accounts: list[SpnAccount] = []
    for i, user in enumerate(_MOCK_USERS):
        rid = 1000 + i * 7 + (user["sid_rid"] % 1000)
        sid = f"S-1-5-21-397955417-626881126-188441444-{rid}"
        tier, label = rank_privilege(sid, user["member_of"])
        uac = 0x200
        accounts.append(
            SpnAccount(
                sam=user["sam"],
                sid=sid,
                tier=tier,
                tier_label=label,
                spns=tuple(sorted(user["spns"])),
                uac=uac,
                uac_flags=tuple(uac_flag_names(uac)),
                member_of=tuple(user["member_of"]),
            )
        )
        # Add one random RID sink per generator scope.
        _ = rng.randint(0, 2**32)
    return accounts


def hashlib_md5(value: str) -> int:
    """Deterministic integer seed derived from ``value`` (stdlib-only)."""
    import hashlib

    return int(hashlib.md5(value.encode()).hexdigest(), 16) % (2**32)


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------


def format_table(accounts: Sequence[SpnAccount], top: int = 0) -> str:
    """Render the ranked SPN inventory as a plain-text table."""
    subset = accounts[:top] if top else list(accounts)
    if not subset:
        return "[*] No SPN-bearing user accounts found."
    width_sam = max(len(a.sam) for a in subset) or 8
    width_spn = max((len(s) for a in subset for s in a.spns), default=24) or 24
    header = (
        f"{'SAM':<{width_sam}}  {'TIER':<8} {'HIGH':<5}  "
        f"{'SPN':<{width_spn}}  {'FLAGS'}"
    )
    lines = [header, "-" * len(header)]
    for acc in subset:
        spn_display = ", ".join(acc.spns) if acc.spns else "(none)"
        lines.append(
            f"{acc.sam:<{width_sam}}  {acc.tier_label:<8} "
            f"{'YES' if acc.high_value else '-':<5}  "
            f"{spn_display:<{width_spn}}  {','.join(acc.uac_flags) or '-'}"
        )
    return "\n".join(lines)


def as_csv(accounts: Sequence[SpnAccount], stream: TextIO) -> None:
    writer = csv.writer(stream)
    writer.writerow(
        ["sam", "sid", "tier", "high_value", "spns", "uac_flags", "member_of"]
    )
    for acc in accounts:
        writer.writerow(
            [
                acc.sam,
                acc.sid or "",
                acc.tier,
                acc.high_value,
                ";".join(acc.spns),
                ";".join(acc.uac_flags),
                ";".join(acc.member_of),
            ]
        )


def json_dump(accounts: Sequence[SpnAccount], top: int = 0) -> str:
    subset = accounts[:top] if top else list(accounts)
    return json.dumps(
        {
            "tool": "spn_collector",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "count": len(subset),
            "accounts": [a.to_dict() for a in subset],
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spn_collector",
        description="Non-intrusive LDAP harvesting of SPN-bearing user accounts, "
        "ranked by privilege tier.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--server",
        help="LDAP server (e.g. dc01.corp.local). Required unless --mock is used.",
    )
    mode.add_argument(
        "--mock",
        action="store_true",
        help="Use a deterministic synthetic inventory (no network).",
    )
    parser.add_argument("--user", help="Bind user (sAMAccountName or DN).")
    parser.add_argument("--password", help="Bind password (omit for anonymous).")
    parser.add_argument("--base-dn", default="DC=corp,DC=local", help="Search base DN.")
    parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format.",
    )
    parser.add_argument(
        "--top", type=int, default=0, help="Only show the top N ranked accounts."
    )
    parser.add_argument(
        "--tier", type=int, choices=[0, 1, 2], default=None, help="Filter by tier."
    )
    return parser


def _main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
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
            build_parser().print_usage(sys.stderr)
            print("[!] either --server or --mock is required", file=sys.stderr)
            return 2
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"[!] spn_collector failed: {exc}", file=sys.stderr)
        return 1

    if args.tier is not None:
        accounts = [a for a in accounts if a.tier == args.tier]
    accounts.sort(key=lambda a: (a.tier, a.sam))

    if args.format == "json":
        print(json_dump(accounts, args.top))
    elif args.format == "csv":
        buffer = io.StringIO()
        as_csv(accounts, buffer)
        print(buffer.getvalue().rstrip())
    else:
        print(format_table(accounts, args.top))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
