"""Shared fixtures for the ad-threat-lab test-suite.

Both JSON catalogs are validated against their schema, and the tools are
tested with *mock* LDAP connectors and synthesized security descriptors — no
live domain, LDAP server, or KDC is ever contacted.
"""

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIGS_DIR = REPO_ROOT / "configs"


@pytest.fixture(scope="session")
def lab_config() -> dict[str, Any]:
    path = CONFIGS_DIR / "lab-config.json"
    assert path.is_file(), f"missing {path}"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def vulnerable_acls() -> dict[str, Any]:
    path = CONFIGS_DIR / "vulnerable-acls.json"
    assert path.is_file(), f"missing {path}"
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Mock LDAP layer
# ---------------------------------------------------------------------------


class FakeValue:
    """Mimic the read-path of an ``ldap3`` attribute (``.value`` / ``.values``)."""

    def __init__(self, value: Any) -> None:
        self.value = value

    @property
    def values(self) -> list[Any]:
        if isinstance(self.value, (list, tuple, set)):
            return list(self.value)
        return [self.value]

    def __iter__(self):
        return iter(self.values)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"FakeValue({self.value!r})"


class FakeEntry:
    """Minimal stand-in for an ``ldap3`` entry (attribute accessor + ``entry_dn``)."""

    def __init__(self, dn: str, attrs: dict[str, Any]) -> None:
        self.entry_dn = dn
        self._attrs = {k.lower(): v for k, v in attrs.items()}

    def __getattr__(self, name: str) -> FakeValue:
        key = name.lower()
        if key not in self._attrs:
            raise AttributeError(name)
        return FakeValue(self._attrs[key])

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"FakeEntry({self.entry_dn!r}, {list(self._attrs)})"


class FakeLdapConnection:
    """Duck-typed ``ldap3.Connection`` returning canned search results.

    ``answers`` maps ``search_filter`` -> list of ``FakeEntry``. ``result``
    mirrors the ldap3 result dict (``result == 0`` means success).
    """

    def __init__(
        self,
        answers: dict[str, list[FakeEntry]] | None = None,
        bound: bool = True,
    ) -> None:
        self.answers = answers or {}
        self.bound = bound
        self.entries: list[FakeEntry] = []
        self.result = {"result": 0, "description": "success"}

    def search(
        self,
        search_base: str,
        search_filter: str,
        attributes: list[str] | None = None,
        search_scope: int = 2,
        paged_size: int | None = None,
    ) -> bool:
        self.entries = self.answers.get(search_filter, self.answers.get("*", []))
        return True


@pytest.fixture
def fake_connection_factory():
    return lambda entries: FakeLdapConnection({"*": entries})


# ---------------------------------------------------------------------------
# Synthetic NT Security Descriptor builder
# ---------------------------------------------------------------------------


def _encode_sid(
    rid: int,
    authority: int = 5,
    prefix: tuple[int, ...] = (21, 397955417, 626881126, 188441444),
) -> bytes:
    """Encode a SID: revision+count, 6-byte authority, LE sub-authorities."""
    subs = list(prefix) + [rid]
    header = bytes([1, len(subs)]) + authority.to_bytes(6, "big")
    body = b""
    for sub in subs:
        body += sub.to_bytes(4, "little")
    return header + body


def _encode_ace(
    ace_type: int,
    mask: int,
    sid: bytes,
    flags: int = 0,
    object_type: bytes | None = None,
) -> bytes:
    """Encode a single ACE; OBJECT_ACE types get a 4-byte object-flag field."""
    is_object = ace_type in {0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0F, 0x10}
    body = mask.to_bytes(4, "little")
    if is_object:
        obj_flags = 0
        if object_type is not None:
            obj_flags |= 1
        body += obj_flags.to_bytes(4, "little")
        if object_type is not None:
            body += object_type
    body += sid
    size = 4 + len(body)
    return bytes([ace_type, flags]) + size.to_bytes(2, "little") + body


def build_security_descriptor(aces: list[bytes], present_dacl: bool = True) -> bytes:
    """Assemble a raw NT Security Descriptor around a set of ACE blobs."""
    revision = 1
    control = 0x8004 if present_dacl else 0x8000  # SDDL_CONTROL + DACL_PRESENT
    # Layout: rev, sbz, control, owner_off, group_off, sacl, dacl
    header_size = 20
    dacl_body = aces
    dacl_layout = bytearray([1, 0, 0, 0, 0, 0, 0, 0])  # rev, sbz, size, count, sbz2
    dacl_layout[2:4] = (8 + sum(len(a) for a in dacl_body)).to_bytes(2, "little")
    dacl_layout[4:6] = len(dacl_body).to_bytes(2, "little")
    for ace in dacl_body:
        dacl_layout += ace

    owner_sid = _encode_sid(500)
    group_sid = _encode_sid(513)
    dacl_offset = header_size + len(owner_sid) + len(group_sid)

    out = bytearray()
    out.append(revision)
    out.append(0)
    out += control.to_bytes(2, "little")
    out += (20).to_bytes(4, "little")  # owner offset
    out += (20 + len(owner_sid)).to_bytes(4, "little")  # group offset
    out += (0).to_bytes(4, "little")  # sacl offset
    out += (
        dacl_offset.to_bytes(4, "little") if present_dacl else (0).to_bytes(4, "little")
    )
    out += owner_sid
    out += group_sid
    out += dacl_layout
    return bytes(out)


@pytest.fixture
def sd_builder():
    return {
        "encode_sid": _encode_sid,
        "encode_ace": _encode_ace,
        "descriptor": build_security_descriptor,
    }


def require_module(name: str) -> Any:
    """Import a project module by dotted name (e.g. 'tools.spn_collector')."""
    spec = importlib.util.find_spec(name)
    if spec is None:
        raise ModuleNotFoundError(name)
    return importlib.import_module(name)


@pytest.fixture
def spn_collector_module():
    return require_module("tools.spn_collector")


@pytest.fixture
def acl_scanner_module():
    return require_module("tools.acl_scanner")


@pytest.fixture
def kerberoast_module():
    return require_module("tools.py_kerberoast")
