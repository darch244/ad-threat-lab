"""acl_scanner — LDAP DACL inspector with a raw NT Security Descriptor parser.

Pure-Python parser for the binary NT Security Descriptor format returned by the
``nTSecurityDescriptor`` attribute of Active Directory objects. It surfaces the
abusive primitives attackers weaponize (GenericAll, WriteDacl, WriteOwner,
GenericWrite, ForceChangePassword, AllowedToAct/RBCD) so the lab's
``configs/vulnerable-acls.json`` catalogue can be validated mechanically and an
auditor can enumerate a real domain read-only.

Two offline modes work without any LDAP server:

  * ``--sd-b64 <base64>``  — parse a raw security-descriptor byte blob
  * ``--sddl 'D:(A;;GA;;;WD)...'`` — parse/validate a textual SDDL string
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

# ---------------------------------------------------------------------------
# NT Security Descriptor / ACE constants
# ---------------------------------------------------------------------------

SE_DACL_PRESENT = 0x0004

ACE_TYPE_NAMES = {
    0x00: "ACCESS_ALLOWED",
    0x01: "ACCESS_DENIED",
    0x02: "SYSTEM_AUDIT",
    0x03: "SYSTEM_ALARM",
    0x05: "ACCESS_ALLOWED_OBJECT",
    0x06: "ACCESS_DENIED_OBJECT",
    0x07: "SYSTEM_AUDIT_OBJECT",
    0x08: "SYSTEM_ALARM_OBJECT",
    0x09: "ACCESS_ALLOWED_CALLBACK",
    0x0A: "ACCESS_DENIED_CALLBACK",
    0x0B: "ACCESS_ALLOWED_CALLBACK_OBJECT",
    0x0C: "ACCESS_DENIED_CALLBACK_OBJECT",
    0x0D: "SYSTEM_AUDIT_CALLBACK",
    0x0E: "SYSTEM_ALARM_CALLBACK",
    0x0F: "SYSTEM_AUDIT_CALLBACK_OBJECT",
    0x10: "SYSTEM_ALARM_CALLBACK_OBJECT",
    0x11: "SYSTEM_MANDATORY_LABEL",
}

_OBJECT_ACE_TYPES = {0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0F, 0x10}
_CALLBACK_ACE_TYPES = {0x09, 0x0A, 0x0B, 0x0C, 0x0F, 0x10}
_ALLOWED_ACE_TYPES = {0x00, 0x05, 0x09, 0x0B}
_DENIED_ACE_TYPES = {0x01, 0x06, 0x0A, 0x0C}

OBJECT_ACE_FLAG_OBJECT_TYPE_PRESENT = 0x00000001
OBJECT_ACE_FLAG_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002

# Access / object rights bits (ADS_RIGHT_* + DS_*)
DELETE = 0x00010000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
DS_CREATE_CHILD = 0x00000001
DS_DELETE_CHILD = 0x00000002
DS_LIST_CHILD = 0x00000004
DS_SELF = 0x00000008
DS_READ_PROP = 0x00000010
DS_WRITE_PROP = 0x00000020
DS_DELETE_TREE = 0x00000040
DS_LIST_OBJECT = 0x00000080
DS_CONTROL_ACCESS = 0x00000100

# Directory-object generic mapping (specific-rights expansion), MS-ADTS 5.1.3.2.
GENERIC_ALL_DACL = 0x000F01FF
GENERIC_WRITE_DACL = 0x0003002B
GENERIC_WRITE_COMMUNITY = 0x000200A9  # commonly published GetWrite expansion
GENERIC_READ_DACL = 0x00020094
GENERIC_EXECUTE_DACL = 0x0002001C

# Control-access right GUIDs that matter to an ACL auditor.
FORCE_CHANGE_PASSWORD_GUID = "00299570-246D-11D0-A768-00AA006E0529"
ALLOWED_TO_ACT_GUID = "3E0F7E18-2C7A-4C10-BA16-1F9D4BD8FC43"

GUID_NAMES = {
    FORCE_CHANGE_PASSWORD_GUID: "User-Force-Change-Password",
    ALLOWED_TO_ACT_GUID: "User-Allowed-To-Act-On-Behalf-Of",
    "BA338B5A-7F5E-4D4C-A89D-2C0C2A5BEE65": "User-Restore-Password",
}


# ---------------------------------------------------------------------------
# SID encoding / decoding helpers
# ---------------------------------------------------------------------------


def decode_sid(data: bytes) -> str:
    """Decode a binary SID blob into its ``S-1-...`` string form.

    Layout: revision(1) | sub-auth-count(1) | identifier-authority(6, BE) |
    sub-authorities(N * 4, LE).
    """
    if len(data) < 8:
        raise ValueError(f"SID blob too short: {len(data)} bytes")
    revision = data[0]
    count = data[1]
    authority = int.from_bytes(data[2:8], "big")
    if len(data) < 8 + count * 4:
        raise ValueError("SID sub-authority count exceeds blob length")
    subs = [
        int.from_bytes(data[8 + i * 4 : 12 + i * 4], "little") for i in range(count)
    ]
    return f"S-{revision}-{authority}-" + "-".join(str(s) for s in subs)


def _rid(sid: str) -> int | None:
    parts = sid.split("-")
    if len(parts) < 5 or parts[2] != "5":  # not an S-1-...-21-... SID
        return None
    try:
        return int(parts[-1])
    except ValueError:
        return None


_DOMAIN_RID_NAMES = {
    500: "Administrator",
    501: "Guest",
    502: "krbtgt",
    512: "Domain Admins",
    513: "Domain Users",
    514: "Domain Guests",
    515: "Domain Computers",
    516: "Domain Controllers",
    517: "Cert Publishers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    521: "Read-only Domain Controllers",
    522: "Cloneable Domain Controllers",
    525: "Protected Users",
    526: "Key Admins",
    527: "Enterprise Key Admins",
}

_BUILTIN_RID_NAMES = {
    544: "BUILTIN\\Administrators",
    545: "BUILTIN\\Users",
    546: "BUILTIN\\Guests",
    547: "BUILTIN\\Power Users",
    548: "BUILTIN\\Account Operators",
    549: "BUILTIN\\Server Operators",
    550: "BUILTIN\\Print Operators",
    551: "BUILTIN\\Backup Operators",
    552: "BUILTIN\\Replicator",
    553: "BUILTIN\\Remote Desktop Users",
    562: "BUILTIN\\Distributed COM Users",
    572: "BUILTIN\\Cryptographic Operators",
}

_SPECIAL_SIDS = {
    "S-1-0-0": "Null SID",
    "S-1-1-0": "Everyone",
    "S-1-5-18": "LOCAL SYSTEM",
    "S-1-5-19": "LOCAL SERVICE",
    "S-1-5-20": "NETWORK SERVICE",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-559": "BUILTIN\\Performance Log Users",
}


def well_known_sid_name(sid: str, domain_name: str | None = None) -> str:
    """Return a human-readable name for well-known SIDs, else the raw SID."""
    if sid in _SPECIAL_SIDS:
        return _SPECIAL_SIDS[sid]
    parts = sid.split("-")
    if len(parts) == 8 and parts[4] == "32":
        name = _BUILTIN_RID_NAMES.get(int(parts[-1]))
        if name:
            return name
    if len(parts) >= 5 and "21" in parts[3:5]:
        rid = _rid(sid)
        if rid is not None and rid in _DOMAIN_RID_NAMES:
            prefix = f"{domain_name or 'CORP'}\\"
            return prefix + _DOMAIN_RID_NAMES[rid]
        if rid == 500 and domain_name:
            return f"{domain_name}\\Administrator"
    return sid


# ---------------------------------------------------------------------------
# ACE / SecurityDescriptor model
# ---------------------------------------------------------------------------


def classify_ace_rights(mask: int, object_type: str | None = None) -> tuple[str, ...]:
    """Map an ACE access-mask + object-type GUID to attacker-relevant labels.

    Ordered by severity so a single ACE can carry multiple labels; the caller
    typically wants the highest-priority primitive.
    """
    labels: list[str] = []
    if (mask & GENERIC_ALL_DACL) == GENERIC_ALL_DACL or (mask & 0x10000000) != 0:
        labels.append("GenericAll")
    if mask & WRITE_DAC:
        labels.append("WriteDacl")
    if mask & WRITE_OWNER:
        labels.append("WriteOwner")
    if (mask & GENERIC_WRITE_DACL) == GENERIC_WRITE_DACL or (
        mask & GENERIC_WRITE_COMMUNITY
    ) == GENERIC_WRITE_COMMUNITY:
        labels.append("GenericWrite")
    if (mask & GENERIC_EXECUTE_DACL) == GENERIC_EXECUTE_DACL and not labels:
        labels.append("GenericExecute")
    if (mask & GENERIC_READ_DACL) == GENERIC_READ_DACL and not labels:
        labels.append("GenericRead")
    if object_type:
        upper = object_type.upper()
        if upper == FORCE_CHANGE_PASSWORD_GUID:
            labels.insert(0, "ForceChangePassword")
        elif upper == ALLOWED_TO_ACT_GUID:
            labels.insert(0, "AllowedToAct")
        elif upper in GUID_NAMES:
            labels.append(GUID_NAMES[upper])
    return tuple(labels)


@dataclass(frozen=True)
class Ace:
    """A parsed Access Control Entry."""

    ace_type: int
    flags: int
    mask: int
    sid: str
    object_type: str | None = None
    inherited_object_type: str | None = None
    condition: str | None = None

    @property
    def type_name(self) -> str:
        return ACE_TYPE_NAMES.get(self.ace_type, f"UNKNOWN({self.ace_type:#04x})")

    @property
    def allowed(self) -> bool:
        return self.ace_type in _ALLOWED_ACE_TYPES

    @property
    def denied(self) -> bool:
        return self.ace_type in _DENIED_ACE_TYPES

    @property
    def rights(self) -> tuple[str, ...]:
        return classify_ace_rights(self.mask, self.object_type)

    def to_dict(self, domain_name: str | None = None) -> dict[str, Any]:
        return {
            "ace_type": self.type_name,
            "flags": self.flags,
            "mask": f"0x{self.mask:08X}",
            "trustee": well_known_sid_name(self.sid, domain_name),
            "sid": self.sid,
            "rights": list(self.rights),
            "object_type": self.object_type,
            "condition": self.condition,
        }


@dataclass
class SecurityDescriptor:
    """Parsed raw NT Security Descriptor as returned by AD."""

    revision: int
    control: int
    owner_sid: str | None
    group_sid: str | None
    aces: list[Ace]

    @property
    def has_dacl(self) -> bool:
        return bool(self.aces) or bool(self.control & SE_DACL_PRESENT)

    def vulnerable_aces(self, min_rights: Sequence[str] | None = None) -> list[Ace]:
        want = set(
            min_rights
            or [
                "GenericAll",
                "WriteDacl",
                "WriteOwner",
                "ForceChangePassword",
                "AllowedToAct",
            ]
        )
        return [
            ace for ace in self.aces if ace.allowed and want.intersection(ace.rights)
        ]

    def to_dict(self, domain_name: str | None = None) -> dict[str, Any]:
        return {
            "revision": self.revision,
            "control": f"0x{self.control:08X}",
            "owner": well_known_sid_name(self.owner_sid, domain_name)
            if self.owner_sid
            else None,
            "group": well_known_sid_name(self.group_sid, domain_name)
            if self.group_sid
            else None,
            "aces": [ace.to_dict(domain_name) for ace in self.aces],
        }


def _format_guid(raw: bytes) -> str:
    """Format 16 raw GUID bytes as a canonical ``8-4-4-4-12`` string (upper)."""
    return (
        raw[0:4].hex().upper()
        + "-"
        + raw[4:6].hex().upper()
        + "-"
        + raw[6:8].hex().upper()
        + "-"
        + raw[8:10].hex().upper()
        + "-"
        + raw[10:16].hex().upper()
    )


def _parse_ace_body(ace_type: int, flags: int, body: bytes) -> Ace | None:
    """Parse the variable-length ACE body (everything after the 4-byte header)."""
    if len(body) < 8:
        return None

    mask = int.from_bytes(body[0:4], "little")
    sid_start = 4
    object_type: str | None = None
    inherited_object_type: str | None = None
    condition: str | None = None

    if ace_type in _OBJECT_ACE_TYPES:
        obj_flags = int.from_bytes(body[4:8], "little")
        sid_start = 8
        if obj_flags & OBJECT_ACE_FLAG_OBJECT_TYPE_PRESENT:
            if len(body) < sid_start + 16:
                return None
            object_type = _format_guid(body[sid_start : sid_start + 16])
            sid_start += 16
        if obj_flags & OBJECT_ACE_FLAG_INHERITED_OBJECT_TYPE_PRESENT:
            if len(body) < sid_start + 16:
                return None
            inherited_object_type = _format_guid(body[sid_start : sid_start + 16])
            sid_start += 16

    if sid_start >= len(body):
        return None

    sid_bytes = body[sid_start:]
    sid_len = 8 + sid_bytes[1] * 4
    if len(sid_bytes) < sid_len:
        return None
    sid = decode_sid(sid_bytes[:sid_len])
    condition_start = sid_start + sid_len

    if ace_type in _CALLBACK_ACE_TYPES:
        rest = body[condition_start:]
        if len(rest) >= 4:
            cond_len = int.from_bytes(rest[0:4], "little")
            if 4 <= len(rest) <= 4 + cond_len:
                condition = rest[4 : 4 + cond_len].decode("utf-8", errors="replace")

    return Ace(
        ace_type=ace_type,
        flags=flags,
        mask=mask,
        sid=sid,
        object_type=object_type,
        inherited_object_type=inherited_object_type,
        condition=condition,
    )


def parse_security_descriptor(data: bytes) -> SecurityDescriptor:
    """Parse a binary NT Security Descriptor (AD ``nTSecurityDescriptor``)."""
    if len(data) < 20:
        raise ValueError(f"Security descriptor too short: {len(data)} bytes")

    revision = data[0]
    control = int.from_bytes(data[2:4], "little")
    owner_offset = int.from_bytes(data[4:8], "little")
    group_offset = int.from_bytes(data[8:12], "little")
    dacl_offset = int.from_bytes(data[16:20], "little")

    def _sid_at(offset: int) -> str | None:
        if not offset or offset >= len(data):
            return None
        return decode_sid(data[offset:])

    aces: list[Ace] = []
    if dacl_offset and (control & SE_DACL_PRESENT) and dacl_offset + 8 <= len(data):
        ace_count = int.from_bytes(data[dacl_offset + 4 : dacl_offset + 6], "little")
        pos = dacl_offset + 8
        for _ in range(ace_count):
            if pos + 4 > len(data):
                break
            ace_type = data[pos]
            flags = data[pos + 1]
            ace_size = int.from_bytes(data[pos + 2 : pos + 4], "little")
            if ace_size < 8 or pos + ace_size > len(data):
                break
            ace = _parse_ace_body(ace_type, flags, data[pos + 4 : pos + ace_size])
            if ace:
                aces.append(ace)
            pos += ace_size

    return SecurityDescriptor(
        revision=revision,
        control=control,
        owner_sid=_sid_at(owner_offset),
        group_sid=_sid_at(group_offset),
        aces=aces,
    )


_SDDL_RIGHT_MAP: dict[str, int] = {
    "GA": GENERIC_ALL_DACL,
    "GX": GENERIC_EXECUTE_DACL,
    "GW": GENERIC_WRITE_DACL,
    "GR": GENERIC_READ_DACL,
    "WD": WRITE_DAC,
    "WO": WRITE_OWNER,
    "RC": READ_CONTROL,
    "SD": DELETE,
    "WP": DS_WRITE_PROP,
    "RP": DS_READ_PROP,
    "CC": DS_CREATE_CHILD,
    "DC": DS_DELETE_CHILD,
    "LC": DS_LIST_CHILD,
    "LD": DS_LIST_OBJECT,
    "SW": DS_SELF,
    "DT": DS_DELETE_TREE,
    "CR": DS_CONTROL_ACCESS,
}

_SDDL_TYPE_MAP = {
    "A": 0x00,
    "D": 0x01,
    "AU": 0x02,
    "OA": 0x05,
    "OD": 0x06,
    "OU": 0x07,
    "AL": 0x0B,
    "OL": 0x0C,
}


def parse_sddl(sddl: str) -> list[Ace]:
    """Parse a ``D:`` DACL section of an SDDL string into ``Ace`` objects.

    Minimal-but-real implementation covering the ACEs produced by common
    LDAP tools (``(A;;rights;objectguid;inheritsid;trusteesid)``). Numeric
    right masks (``0x...``) are supported verbatim.
    """
    match = re.search(r"D:(?:P|AR|AI|AU)?((?:\([^)]*\))+)", sddl, re.IGNORECASE)
    if not match:
        return []
    dacl_str = match.group(1)
    aces: list[Ace] = []
    for token in re.findall(r"\(([^)]*)\)", dacl_str):
        parts = [p.strip() for p in token.split(";")]
        if len(parts) < 6:
            continue
        ace_type, flags, rights, obj_guid, inherit_guid, sid = parts[:6]
        ace_type_code = _SDDL_TYPE_MAP.get(ace_type.upper(), 0x00)
        mask = 0
        for right in re.findall(r"[A-Za-z]{2}|0x[0-9A-Fa-f]+", rights):
            if right.lower().startswith("0x"):
                mask |= int(right, 16)
            else:
                mask |= _SDDL_RIGHT_MAP.get(right.upper(), 0)
        object_type = obj_guid.upper() if obj_guid else None
        aces.append(
            Ace(
                ace_type=ace_type_code,
                flags=int(flags, 16) if flags else 0,
                mask=mask,
                sid=sid,
                object_type=object_type,
                inherited_object_type=inherit_guid.upper() if inherit_guid else None,
            )
        )
    return aces


def build_sddl(descriptor: SecurityDescriptor) -> str:
    """Serialize a ``SecurityDescriptor`` back to a compact SDDL DACL string."""

    def _rights_str(mask: int) -> str:
        labels = classify_ace_rights(mask)
        if "GenericAll" in labels:
            return "GA"
        if "GenericWrite" in labels:
            return "GW"
        if "GenericRead" in labels:
            return "GR"
        rights: list[str] = []
        if mask & WRITE_DAC:
            rights.append("WD")
        if mask & WRITE_OWNER:
            rights.append("WO")
        if mask & DS_WRITE_PROP:
            rights.append("WP")
        if mask & DS_READ_PROP:
            rights.append("RP")
        if mask & DS_CONTROL_ACCESS:
            rights.append("CR")
        if mask & DELETE:
            rights.append("SD")
        return "".join(rights) if rights else f"0x{mask:08X}"

    ace_strs: list[str] = []
    for ace in descriptor.aces:
        type_token = {0x00: "A", 0x01: "D", 0x05: "OA", 0x06: "OD"}.get(
            ace.ace_type, "A"
        )
        ace_strs.append(f"({type_token};;{_rights_str(ace.mask)};;;{ace.sid})")
    return "(D;P;" + "".join(ace_strs) + ")"


# ---------------------------------------------------------------------------
# LDAP collection (ldap3 is imported lazily so the parser stays import-safe)
# ---------------------------------------------------------------------------


class LdapSearchApi(Protocol):
    """Duck-typed subset of ``ldap3.Connection`` used by the collectors."""

    bound: bool
    entries: Any

    def search(
        self,
        search_base: str,
        search_filter: str,
        attributes: Sequence[str],
        search_scope: int = ...,
        paged_size: int | None = ...,
    ) -> bool: ...


class LdapEntryLike(Protocol):
    """Duck-typed subset of ``ldap3`` entry attribute access."""

    entry_dn: str

    def __getattr__(self, name: str) -> Any: ...


def _attr_values(entry: Any, name: str) -> list[Any]:
    """Read an attribute from an ldap3-like entry, tolerating absence."""
    try:
        attr = getattr(entry, name, None)
    except Exception:  # noqa: BLE001 - attribute access on a dynamic ldap3 object
        return []
    if attr is None:
        return []
    values = getattr(attr, "values", None)
    if values is None:
        return []
    return [v for v in values if v is not None]


def collect_acl_entries(
    connection: LdapSearchApi,
    base_dn: str,
    max_entries: int = 0,
) -> list[tuple[str, SecurityDescriptor]]:
    """Return ``(distinguished_name, parsed_descriptor)`` for LDAP objects.

    Read-only: retrieves ``nTSecurityDescriptor`` for every object under
    ``base_dn`` and parses it in pure Python.
    """
    import ldap3  # type: ignore[import-untyped]

    attributes = [
        "distinguishedName",
        "nTSecurityDescriptor",
        "objectSid",
        "sAMAccountName",
        "userAccountControl",
    ]
    ok = connection.search(
        base_dn,
        "(objectClass=*)",
        attributes=attributes,
        search_scope=ldap3.SUBTREE,
        paged_size=500,
    )
    if not ok:
        return []

    results: list[tuple[str, SecurityDescriptor]] = []
    for entry in connection.entries:  # type: ignore[union-attr]
        raw_blocks = _attr_values(entry, "nTSecurityDescriptor")
        if not raw_blocks:
            continue
        dn = getattr(entry, "entry_dn", None) or str(
            _attr_values(entry, "distinguishedName")[0]
        )
        try:
            descriptor = parse_security_descriptor(bytes(raw_blocks[0]))
        except (ValueError, TypeError):
            continue
        results.append((str(dn), descriptor))
        if max_entries and len(results) >= max_entries:
            break
    return results


def collect_rbcd_principals(
    connection: LdapSearchApi, base_dn: str
) -> list[dict[str, Any]]:
    """Find objects with ``msDS-AllowedToActOnBehalfOfOtherIdentity`` set (RBCD)."""
    import ldap3

    ok = connection.search(
        base_dn,
        "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
        attributes=[
            "distinguishedName",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
        ],
        search_scope=ldap3.SUBTREE,
    )
    if not ok:
        return []
    findings: list[dict[str, Any]] = []
    for entry in connection.entries:  # type: ignore[union-attr]
        blobs = _attr_values(entry, "msDS-AllowedToActOnBehalfOfOtherIdentity")
        if not blobs:
            continue
        dn = getattr(entry, "entry_dn", None) or ""
        principals: list[str] = []
        try:
            sd = parse_security_descriptor(bytes(blobs[0]))
            principals = [ace.sid for ace in sd.aces if ace.allowed]
        except (ValueError, TypeError):
            principals = [f"<unparsable:{len(bytes(blobs[0]))} bytes>"]
        findings.append(
            {
                "target": str(dn),
                "principal_sids": principals,
                "principals": [well_known_sid_name(p) for p in principals],
            }
        )
    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="acl_scanner",
        description="Inspect Active Directory DACLs and flag attacker-relevant "
        "primitives (GenericAll / WriteDacl / WriteOwner / GenericWrite / "
        "ForceChangePassword / AllowedToAct).",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--server",
        help="LDAP/GC server hostname (e.g. dc01.corp.local or 192.168.56.10).",
    )
    group.add_argument(
        "--sd-b64",
        metavar="B64",
        help="Offline: parse a single base64 security-descriptor blob.",
    )
    group.add_argument(
        "--sddl",
        metavar="SDDL",
        help="Offline: parse/validate an SDDL DACL string, e.g. "
        "'D:(A;;GA;;;WD)(A;;WP;00299570-246d-11d0-a768-00aa006e0529;;PS)'.",
    )
    parser.add_argument("--user", help="Bind DN or sAMAccountName.")
    parser.add_argument("--password", help="Bind password (omit for anonymous).")
    parser.add_argument("--base-dn", default="DC=corp,DC=local", help="Search base DN.")
    parser.add_argument(
        "--min-right",
        action="append",
        default=None,
        choices=[
            "GenericAll",
            "WriteDacl",
            "WriteOwner",
            "GenericWrite",
            "ForceChangePassword",
            "AllowedToAct",
        ],
        help="Only print ACEs carrying this right (repeatable).",
    )
    parser.add_argument(
        "--rbcd", action="store_true", help="Also scan for RBCD primitives."
    )
    parser.add_argument(
        "--max-entries", type=int, default=0, help="Cap parsed objects (0 = all)."
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit JSON instead of a table."
    )
    parser.add_argument(
        "--domain-name", default=None, help="NETBIOS name for friendly SID labels."
    )
    return parser


def _main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.sd_b64:
            descriptor = parse_security_descriptor(base64.b64decode(args.sd_b64))
            items = [("(base64 blob)", descriptor)]
        elif args.sddl:
            aces = parse_sddl(args.sddl)
            descriptor = SecurityDescriptor(
                revision=1,
                control=SE_DACL_PRESENT,
                owner_sid=None,
                group_sid=None,
                aces=aces,
            )
            items = [("(sddl string)", descriptor)]
        else:
            connection = _connect(args)
            items = collect_acl_entries(connection, args.base_dn, args.max_entries)
            if args.rbcd:
                rbcd = collect_rbcd_principals(connection, args.base_dn)
                for finding in rbcd:
                    print(json.dumps(finding, indent=2))
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"[!] acl_scanner failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(
            json.dumps(
                [
                    {
                        "object": dn,
                        "descriptor": sd.to_dict(args.domain_name),
                        "vulnerabilities": [
                            ace.to_dict(args.domain_name)
                            for ace in sd.vulnerable_aces(args.min_right)
                        ],
                    }
                    for dn, sd in items
                ],
                indent=2,
            )
        )
        return 0

    if not items:
        print("[*] No objects with DACLs found.")
        return 0

    for dn, sd in items:
        print(f"\n== {dn}")
        print(f"   Owner: {sd.owner_sid}  Control: {sd.control:#06x}")
        vulnerable = sd.vulnerable_aces(args.min_right)
        if not vulnerable:
            print("   No attacker-relevant ACEs.")
            continue
        for ace in vulnerable:
            print(
                f"   [{ace.type_name}] mask={ace.mask:#10x} rights={','.join(ace.rights)}"
                f" trustee={well_known_sid_name(ace.sid, args.domain_name)}"
            )
    return 0


def _connect(args: argparse.Namespace) -> LdapSearchApi:
    import ldap3

    server = ldap3.Server(args.server, get_info=ldap3.ALL, use_ssl=True)
    conn = ldap3.Connection(
        server,
        user=args.user,
        password=args.password,
        auto_bind=True,
        authentication=ldap3.SIMPLE if args.user else ldap3.ANONYMOUS,
    )
    return conn  # type: ignore[return-value]


if __name__ == "__main__":
    raise SystemExit(_main())
