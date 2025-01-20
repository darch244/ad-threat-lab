"""Validation of configs/lab-config.json and configs/vulnerable-acls.json.

These tests act as the lab's contract: provisioning, misconfig injection, and
the custom tools all agree on the same schema, so a config that breaks a tool
fails the suite before it ever reaches a VM.
"""

import json
from pathlib import Path

CONFIGS_DIR = Path(__file__).resolve().parent.parent / "configs"

ALLOWED_TIERS = {0, 1, 2}
ALLOWED_ACL_RIGHTS = {
    "GenericAll",
    "WriteDacl",
    "WriteOwner",
    "ForceChangePassword",
    "GenericWrite",
    "RBCD",
}
FORCE_CHANGE_PASSWORD_GUID = "00299570-246D-11D0-A768-00AA006E0529"


def _config(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def test_config_files_exist_and_parse():
    for name in ("lab-config.json", "vulnerable-acls.json"):
        payload = _config(CONFIGS_DIR / name)
        assert isinstance(payload, dict)
        assert payload


def test_lab_config_domain_schema(lab_config):
    domain = lab_config["domain"]
    assert domain["fqdn"] == "corp.local"
    assert domain["netbios"] == "CORP"
    assert domain["base_dn"].endswith("DC=corp,DC=local")
    assert lab_config["env"]["dc01_ip"] == "192.168.56.10"


def test_ous_are_unique_and_under_base_dn(lab_config):
    paths = [ou["path"] for ou in lab_config["ous"]]
    assert len(paths) == len(set(paths)), "OU paths must be unique"
    for ou in lab_config["ous"]:
        assert ou["path"].startswith("OU=")
        assert ou["path"].endswith("DC=corp,DC=local")
        assert isinstance(ou["protected_from_accidental_deletion"], bool)


def test_tier_ous_present(lab_config):
    names = {ou["name"] for ou in lab_config["ous"]}
    assert {"Tier0", "Tier1", "Tier2", "ServiceAccounts", "PrivilegedAccess"} <= names


def test_users_unique_and_valid(lab_config):
    sams = [u["sam"] for u in lab_config["users"]]
    assert len(sams) == len(set(sams)), "user sAMAccountName must be unique"
    for user in lab_config["users"]:
        assert user["tier"] in ALLOWED_TIERS
        assert user["ou_path"].startswith("OU=")
        assert isinstance(user["group_membership"], list)
        assert isinstance(user["high_value"], bool)
        if "spns" in user:
            assert isinstance(user["spns"], list) and user["spns"]


def test_krb_canaries_exist(lab_config):
    sams = {u["sam"] for u in lab_config["users"]}
    assert "asrep-user" in sams, "AS-REP canary user missing"
    assert "svc-sql" in sams, "Kerberoastable service account missing"
    assert "darc-admin" in sams, "Domain Admin user missing"


def test_asrep_flag_declared_consistently(lab_config):
    asrep = next(u for u in lab_config["users"] if u["sam"] == "asrep-user")
    assert asrep["does_not_require_preauth"] is True
    assert (
        len(
            {u["sam"] for u in lab_config["users"] if u.get("does_not_require_preauth")}
        )
        == 1
    )


def test_group_memberships_resolve(lab_config):
    groups = {g["name"] for g in lab_config["groups"]}
    builtins = {
        "Domain Admins",
        "Enterprise Admins",
        "Domain Users",
        "Backup Operators",
    }
    for user in lab_config["users"]:
        unknown = set(user["group_membership"]) - groups - builtins
        assert not unknown, f"{user['sam']} references unknown groups: {unknown}"


def test_every_user_lives_in_a_configured_ou(lab_config):
    ou_paths = {ou["path"] for ou in lab_config["ous"]}
    for user in lab_config["users"]:
        assert user["ou_path"] in ou_paths, (
            f"{user['sam']} OU not configured: {user['ou_path']}"
        )


def test_spn_catalog_is_covered_by_user_spns(lab_config):
    user_spns = {spn for u in lab_config["users"] for spn in u.get("spns", [])}
    for spn in lab_config["spns"]:
        assert spn in user_spns, f"global SPN {spn} not attached to any user"
    for u in lab_config["users"]:
        for spn in u.get("spns", []):
            assert spn in lab_config["spns"], (
                f"user SPN {spn} missing from global catalog"
            )


def test_spns_have_valid_syntax(lab_config):
    for spn in lab_config["spns"]:
        assert "/" in spn, f"SPN must contain a service/host pair: {spn}"


def test_high_value_targets_resolve(lab_config):
    sids = {"krbtgt"}
    users = {u["sam"] for u in lab_config["users"]}
    for target in lab_config["high_value_targets"]:
        if target["type"] == "user":
            assert target["sam"] in users | sids, f"unknown HV target: {target['sam']}"


def test_delegation_entries_consistent(lab_config):
    sams = {u["sam"] for u in lab_config["users"]}
    for entry in lab_config["delegation"]:
        assert entry["sam"] in sams, f"delegation principal missing: {entry['sam']}"
        assert entry["type"] in {"unconstrained", "constrained"}
        if entry["type"] == "constrained":
            assert entry["allowed_to_act_on"], (
                "constrained delegation needs allowed_to_act_on"
            )
            assert isinstance(entry["allowed_to_act_on"], list)


# ---------------------------------------------------------------------------
# vulnerable-acls.json
# ---------------------------------------------------------------------------


def test_acl_rights_are_in_allowed_set(vulnerable_acls):
    allowed = set(vulnerable_acls["allowed_rights"])
    assert allowed == ALLOWED_ACL_RIGHTS
    for acl in vulnerable_acls["acls"]:
        assert acl["right"] in allowed, f"unsupported right: {acl['right']}"


def test_acl_ids_unique(vulnerable_acls):
    ids = [acl["id"] for acl in vulnerable_acls["acls"]]
    assert len(ids) == len(set(ids)), "ACL ids must be unique"


def test_acl_effect_and_commands_present(vulnerable_acls):
    for acl in vulnerable_acls["acls"]:
        for key in ("target", "trustee", "effect", "inject_command", "purge_command"):
            assert acl.get(key), f"{acl['id']} missing {key}"


def test_required_acl_primitives_present(vulnerable_acls):
    rights = {acl["right"] for acl in vulnerable_acls["acls"]}
    assert {"GenericAll", "WriteDacl", "ForceChangePassword", "RBCD"} <= rights


def test_acl_access_masks_parse(vulnerable_acls):
    for acl in vulnerable_acls["acls"]:
        if "access_mask" in acl:
            int(acl["access_mask"], 16)


def test_fcp_acl_uses_correct_guid(vulnerable_acls):
    fcp = next(
        a for a in vulnerable_acls["acls"] if a["right"] == "ForceChangePassword"
    )
    assert fcp["guid"] == "User-Force-Change-Password"
    assert FORCE_CHANGE_PASSWORD_GUID in ("00299570-246D-11D0-A768-00AA006E0529",)


def test_rbcd_target_is_dc01(vulnerable_acls):
    rbcd = next(a for a in vulnerable_acls["acls"] if a["right"] == "RBCD")
    assert rbcd["target"] == "DC01$"
    assert rbcd["attribute"] == "msDS-AllowedToActOnBehalfOfOtherIdentity"


def test_acl_trustees_are_lab_users(vulnerable_acls, lab_config):
    users = {u["sam"] for u in lab_config["users"]}
    for acl in vulnerable_acls["acls"]:
        assert acl["trustee"] in users, f"{acl['id']} trustee not in lab users"


def test_acl_targets_resolve_in_lab(vulnerable_acls, lab_config):
    group_names = {g["name"] for g in lab_config["groups"]} | {
        "Tier1-Admins",
        "SQL-Admins",
    }
    user_names = {u["sam"] for u in lab_config["users"]}
    for acl in vulnerable_acls["acls"]:
        if acl["target_type"] == "group":
            assert acl["target"] in group_names, f"{acl['id']} unknown group"
        elif acl["target_type"] == "user":
            assert acl["target"] in user_names, f"{acl['id']} unknown user"
        elif acl["target_type"] == "computer":
            assert acl["target"].endswith("$"), f"{acl['id']} bad computer target"
