"""ad-threat-lab — custom Python tooling for the CORP.LOCAL lab.

Pure-Python 3.11+ offense/audit helpers. No placeholders, full type hints,
argparse CLI, and defensive error handling. All three tools work fully
offline (mock / fixture modes) so the test-suite never needs a live domain:

  - spn_collector:  non-intrusive LDAP SPN harvesting with privilege ranking
  - acl_scanner:    LDAP DACL inspector & raw NT Security Descriptor parser
  - py_kerberoast:  SPN discovery + TGS-REQ hash extraction (RC4 / AES)

Submodules are exposed lazily via ``__getattr__`` so ``python -m tools.X``
runs cleanly without a runpy re-import warning.
"""

__version__ = "0.1.0"

__all__ = [
    "ACE_TYPE_NAMES",
    "FORCE_CHANGE_PASSWORD_GUID",
    "PRIVILEGED_RIDS",
    "Ace",
    "KdcRequestor",
    "KdsError",
    "KerberoastError",
    "KerberosHarvester",
    "Krb5TgsMaterial",
    "LdapEntryLike",
    "LdapSearchApi",
    "SecurityDescriptor",
    "SpnAccount",
    "__version__",
    "build_krb5tgs23_hash",
    "build_sddl",
    "classify_ace_rights",
    "collect_acl_entries",
    "collect_spns",
    "parse_sddl",
    "parse_security_descriptor",
    "rank_privilege",
    "uac_flag_names",
    "well_known_sid_name",
]

_MODULES = {
    "acl_scanner": "tools.acl_scanner",
    "py_kerberoast": "tools.py_kerberoast",
    "spn_collector": "tools.spn_collector",
}

_NAME_TO_MODULE = {
    name: f"tools.{module}"
    for module, names in {
        "acl_scanner": [
            "ACE_TYPE_NAMES",
            "FORCE_CHANGE_PASSWORD_GUID",
            "Ace",
            "LdapEntryLike",
            "LdapSearchApi",
            "SecurityDescriptor",
            "build_sddl",
            "classify_ace_rights",
            "collect_acl_entries",
            "parse_sddl",
            "parse_security_descriptor",
            "well_known_sid_name",
        ],
        "py_kerberoast": [
            "KdcRequestor",
            "KdsError",
            "KerberoastError",
            "KerberosHarvester",
            "Krb5TgsMaterial",
            "build_krb5tgs23_hash",
        ],
        "spn_collector": [
            "PRIVILEGED_RIDS",
            "SpnAccount",
            "collect_spns",
            "rank_privilege",
            "uac_flag_names",
        ],
    }.items()
    for name in names
}

_MODULE_NAMES = set(_MODULES)


def __getattr__(name: str) -> object:
    """Import a tool module / re-export a public name on first use."""
    import importlib

    if name in _NAME_TO_MODULE:
        module = importlib.import_module(_NAME_TO_MODULE[name])
        return getattr(module, name)
    if name in _MODULE_NAMES:
        module = importlib.import_module(_MODULES[name])
        globals()[name] = module
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")