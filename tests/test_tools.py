"""Unit tests for tools/ — all run offline against mock LDAP / Kerberos /
raw security-descriptor fixtures. No live domain, LDAP server or KDC is
contacted.
"""

import json

from tests.conftest import FakeEntry, build_security_descriptor

FORCE_CHANGE_PASSWORD_GUID_BYTES = bytes.fromhex("00299570246D11D0A76800AA006E0529")


# ---------------------------------------------------------------------------
# acl_scanner — SID helpers
# ---------------------------------------------------------------------------


def test_decode_sid_roundtrip(acl_scanner_module, sd_builder):
    encoded = sd_builder["encode_sid"](512)
    assert acl_scanner_module.decode_sid(encoded) == (
        "S-1-5-21-397955417-626881126-188441444-512"
    )


def test_decode_sid_rejects_short_blob(acl_scanner_module):
    try:
        acl_scanner_module.decode_sid(b"\x01\x02\x03")
    except ValueError:
        return
    raise AssertionError("short SID blob should raise ValueError")


def test_well_known_sid_names(acl_scanner_module):
    wkn = acl_scanner_module.well_known_sid_name
    assert wkn("S-1-5-18") == "LOCAL SYSTEM"
    assert wkn("S-1-1-0") == "Everyone"
    assert wkn("S-1-5-32-544") == "BUILTIN\\Administrators"
    assert wkn("S-1-5-21-397955417-626881126-188441444-512", "CORP") == (
        "CORP\\Domain Admins"
    )
    assert wkn("S-1-5-21-397955417-626881126-188441444-502", "CORP") == ("CORP\\krbtgt")
    assert wkn("S-1-5-6") == "S-1-5-6"


# ---------------------------------------------------------------------------
# acl_scanner — NT Security Descriptor parser
# ---------------------------------------------------------------------------


def test_parse_sd_generic_all(acl_scanner_module, sd_builder):
    ace = sd_builder["encode_ace"](0x00, 0xF01FF, sd_builder["encode_sid"](512))
    sd = acl_scanner_module.parse_security_descriptor(build_security_descriptor([ace]))
    assert sd.has_dacl
    assert sd.owner_sid == "S-1-5-21-397955417-626881126-188441444-500"
    assert len(sd.aces) == 1
    ace_info = sd.aces[0]
    assert ace_info.allowed and not ace_info.denied
    assert "GenericAll" in ace_info.rights
    assert sd.vulnerable_aces()
    assert ace_info.sid == "S-1-5-21-397955417-626881126-188441444-512"


def test_parse_sd_write_dacl(acl_scanner_module, sd_builder):
    ace = sd_builder["encode_ace"](0x00, 0x40000, sd_builder["encode_sid"](513))
    sd = acl_scanner_module.parse_security_descriptor(build_security_descriptor([ace]))
    assert "WriteDacl" in sd.aces[0].rights


def test_parse_sd_write_owner(acl_scanner_module, sd_builder):
    ace = sd_builder["encode_ace"](0x00, 0x80000, sd_builder["encode_sid"](513))
    sd = acl_scanner_module.parse_security_descriptor(build_security_descriptor([ace]))
    assert "WriteOwner" in sd.aces[0].rights


def test_parse_sd_force_change_password_object_ace(acl_scanner_module, sd_builder):
    ace = sd_builder["encode_ace"](
        0x05,
        0x20,
        sd_builder["encode_sid"](513),
        object_type=FORCE_CHANGE_PASSWORD_GUID_BYTES,
    )
    sd = acl_scanner_module.parse_security_descriptor(build_security_descriptor([ace]))
    aces_fcp = [a for a in sd.aces if "ForceChangePassword" in a.rights]
    assert len(aces_fcp) == 1


def test_parse_sd_no_dacl_yields_empty_aces(acl_scanner_module, sd_builder):
    sd = acl_scanner_module.parse_security_descriptor(
        build_security_descriptor([], present_dacl=False)
    )
    assert sd.aces == []
    assert not sd.has_dacl


def test_parse_sd_denied_ace_not_vulnerable(acl_scanner_module, sd_builder):
    ace = sd_builder["encode_ace"](0x01, 0xF01FF, sd_builder["encode_sid"](513))
    sd = acl_scanner_module.parse_security_descriptor(build_security_descriptor([ace]))
    assert sd.aces[0].denied
    assert sd.vulnerable_aces() == []


def test_parse_sd_multiple_aces(acl_scanner_module, sd_builder):
    a1 = sd_builder["encode_ace"](0x00, 0x20094, sd_builder["encode_sid"](513))
    a2 = sd_builder["encode_ace"](0x00, 0xF01FF, sd_builder["encode_sid"](512))
    sd = acl_scanner_module.parse_security_descriptor(
        build_security_descriptor([a1, a2])
    )
    assert len(sd.aces) == 2


def test_collect_acl_entries_via_fake_ldap(
    acl_scanner_module, fake_connection_factory, sd_builder
):
    ace = sd_builder["encode_ace"](0x00, 0xF01FF, sd_builder["encode_sid"](512))
    descriptor = build_security_descriptor([ace])
    conn = fake_connection_factory(
        [
            FakeEntry(
                "CN=svc-sql,OU=ServiceAccounts,DC=corp,DC=local",
                {"nTSecurityDescriptor": descriptor},
            )
        ]
    )
    results = acl_scanner_module.collect_acl_entries(conn, "DC=corp,DC=local")
    assert len(results) == 1
    dn, sd = results[0]
    assert dn == "CN=svc-sql,OU=ServiceAccounts,DC=corp,DC=local"
    assert "GenericAll" in sd.aces[0].rights


def test_collect_rbcd_principals(
    acl_scanner_module, fake_connection_factory, sd_builder
):
    # AllowedToAct is an object ACE whose object-type GUID is 3E0F7E18-...
    ace = sd_builder["encode_ace"](
        0x05,
        0x100,
        sd_builder["encode_sid"](777),
        object_type=bytes.fromhex("3E0F7E182C7A4C10BA161F9D4BD8FC43"),
    )
    descriptor = build_security_descriptor([ace])
    conn = fake_connection_factory(
        [
            FakeEntry(
                "CN=DC01,OU=Domain Controllers,DC=corp,DC=local",
                {"msDS-AllowedToActOnBehalfOfOtherIdentity": descriptor},
            )
        ]
    )
    findings = acl_scanner_module.collect_rbcd_principals(conn, "DC=corp,DC=local")
    assert len(findings) == 1
    assert findings[0]["target"] == "CN=DC01,OU=Domain Controllers,DC=corp,DC=local"
    assert findings[0]["principal_sids"] == [
        "S-1-5-21-397955417-626881126-188441444-777"
    ]


# ---------------------------------------------------------------------------
# acl_scanner — SDDL offline mode
# ---------------------------------------------------------------------------


def test_parse_sddl_generic_all_and_fcp(acl_scanner_module):
    aces = acl_scanner_module.parse_sddl(
        "D:(A;;GA;;;WD)(A;;WP;00299570-246d-11d0-a768-00aa006e0529;;PS)"
    )
    assert len(aces) == 2
    assert "GenericAll" in aces[0].rights
    assert aces[1].rights.count("ForceChangePassword")
    assert aces[1].object_type == "00299570-246D-11D0-A768-00AA006E0529"


def test_parse_sddl_numeric_mask_and_multi_trustee(acl_scanner_module):
    aces = acl_scanner_module.parse_sddl(
        "D:(A;;0x0F01FF;;;S-1-5-21-397955417-626881126-188441444-512)"
    )
    assert len(aces) == 1
    assert aces[0].mask == 0xF01FF


def test_sddl_cli_offline(acl_scanner_module):
    rc = acl_scanner_module._main(["--sddl", "D:(A;;GA;;;WD)"])
    assert rc == 0


# ---------------------------------------------------------------------------
# spn_collector
# ---------------------------------------------------------------------------


def _spn_entry(
    sam="svc-sql",
    rid=2234,
    member_of=("CN=SQL-Admins",),
    spns=("MSSQLSvc/sql01.corp.local:1433", "MSSQLSvc/sql01.corp.local:sql01"),
    uac=0x200,
    spectral_extra=None,
):
    attrs = {
        "sAMAccountName": sam,
        "servicePrincipalName": list(spns),
        "objectSid": bytes([1, 5])
        + (5).to_bytes(6, "big")
        + (21).to_bytes(4, "little")
        + (397955417).to_bytes(4, "little")
        + (626881126).to_bytes(4, "little")
        + (188441444).to_bytes(4, "little")
        + (rid).to_bytes(4, "little"),
        "userAccountControl": uac,
        "memberOf": list(member_of),
    }
    if spectral_extra:
        attrs.update(spectral_extra)
    return FakeEntry(f"CN={sam},OU=ServiceAccounts,DC=corp,DC=local", attrs)


def test_collect_spns_parses_and_ranks(spn_collector_module, fake_connection_factory):
    conn = fake_connection_factory([_spn_entry()])
    accounts = spn_collector_module.collect_spns(conn, "DC=corp,DC=local")
    assert len(accounts) == 1
    acc = accounts[0]
    assert acc.sam == "svc-sql"
    assert acc.tier == 1
    assert acc.tier_label == "tier1"
    assert acc.spns == (
        "MSSQLSvc/sql01.corp.local:1433",
        "MSSQLSvc/sql01.corp.local:sql01",
    )
    assert acc.sid == "S-1-5-21-397955417-626881126-188441444-2234"


def test_collect_spns_ranks_domain_admin_tier0(
    spn_collector_module, fake_connection_factory
):
    entry = _spn_entry(
        sam="darc-admin",
        rid=512,
        member_of=("CN=Domain Admins,CN=Users,DC=corp,DC=local",),
        spns=("cifs/adm.corp.local",),
    )
    conn = fake_connection_factory([entry])
    accounts = spn_collector_module.collect_spns(conn, "DC=corp,DC=local")
    assert accounts[0].tier == 0
    assert accounts[0].high_value is True


def test_collect_spns_tier2_and_uac_flags(
    spn_collector_module, fake_connection_factory
):
    entry = _spn_entry(
        sam="t2canary",
        rid=5555,
        member_of=("CN=Domain Users,CN=Users,DC=corp,DC=local",),
        spns=("printer/canary.corp.local",),
        uac=0x400200,
    )
    conn = fake_connection_factory([entry])
    accounts = spn_collector_module.collect_spns(conn, "DC=corp,DC=local")
    acc = accounts[0]
    assert acc.tier == 2
    assert "DONT_REQUIRE_PREAUTH" in acc.uac_flags
    assert "NORMAL_ACCOUNT" in acc.uac_flags


def test_collect_spns_empty_domain(spn_collector_module, fake_connection_factory):
    accounts = spn_collector_module.collect_spns(
        fake_connection_factory([]), "DC=corp,DC=local"
    )
    assert accounts == []


def test_uac_flag_names(spn_collector_module):
    flags = spn_collector_module.uac_flag_names(0x402002)
    assert "DONT_REQUIRE_PREAUTH" in flags
    assert "ACCOUNTDISABLE" in flags


def test_rank_privilege_group_basenames(spn_collector_module):
    assert spn_collector_module.rank_privilege(
        "S-1-5-21-397955417-626881126-188441444-9999",
        ["CN=Enterprise Admins,CN=Users,DC=corp,DC=local"],
    ) == (0, "tier0")
    assert spn_collector_module.rank_privilege(
        None,
        ["CN=Backup Operators,CN=Builtin,DC=corp,DC=local"],
    ) == (1, "tier1")


def test_mock_inventory_is_deterministic(spn_collector_module):
    first = spn_collector_module.generate_mock_spn_accounts()
    second = spn_collector_module.generate_mock_spn_accounts()
    assert [a.to_dict() for a in first] == [a.to_dict() for a in second]
    assert len(first) == 5
    assert first[0].tier == 0  # darc-admin via Domain Admins membership


def test_json_dump_shape(spn_collector_module):
    accounts = spn_collector_module.generate_mock_spn_accounts()
    payload = json.loads(spn_collector_module.json_dump(accounts))
    assert payload["tool"] == "spn_collector"
    assert payload["count"] == len(accounts)
    assert payload["accounts"][1]["sam"] == "svc-sql"


def test_collect_spns_cli_mock(spn_collector_module):
    assert spn_collector_module._main(["--mock", "--format", "json"]) == 0


# ---------------------------------------------------------------------------
# py_kerberoast — hash composition + harness
# ---------------------------------------------------------------------------


def test_build_rc4_hash(kerberoast_module):
    h = kerberoast_module.build_krb5tgs23_hash(
        user="svc-sql",
        realm="CORP.LOCAL",
        spn="MSSQLSvc/sql01.corp.local:1433",
        etype_name="23",
        checksum_hex="abcd",
        cipher_hex="1234",
    )
    assert (
        h
        == "$krb5tgs$23$*svc-sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$23$abcd$1234"
    )


def test_build_aes_hash(kerberoast_module):
    h = kerberoast_module.build_krb5tgs23_hash(
        user="svc-httpd",
        realm="CORP.LOCAL",
        spn="HTTP/web01.corp.local",
        etype_name="aes256-cts-hmac-sha1-96",
        checksum_hex="001122",
        cipher_hex="ffeedd",
    )
    assert h.startswith("$krb5tgs$23$*svc-httpd$CORP.LOCAL$HTTP/web01.corp.local*")
    assert "aes256-cts-hmac-sha1-96" in h
    assert h.endswith("$001122$ffeedd")


def test_split_checksum_rc4_at_end(kerberoast_module):
    checksum, cipher = kerberoast_module.split_checksum(b"s" * 8 + b"c" * 16, etype=23)
    assert checksum == "63" * 16
    assert cipher == "73" * 8


def test_split_checksum_aes_at_start(kerberoast_module):
    checksum, cipher = kerberoast_module.split_checksum(b"c" * 16 + b"b" * 10, etype=17)
    assert checksum == "63" * 16
    assert cipher == "62" * 10


def test_krb5tgs_material_to_hash(kerberoast_module):
    material = kerberoast_module.Krb5TgsMaterial(
        user="svc-sql",
        realm="CORP.LOCAL",
        spn="MSSQLSvc/sql01.corp.local:1433",
        etype=23,
        checksum_hex="aa",
        cipher_hex="bb",
    )
    assert material.etype_name == "23"
    assert material.to_hash().startswith("$krb5tgs$23$*svc-sql$CORP.LOCAL$")


def test_harvester_roast_with_fake_requestor(kerberoast_module):
    material = kerberoast_module.Krb5TgsMaterial(
        user="u",
        realm="CORP.LOCAL",
        spn="cifs/h",
        etype=23,
        checksum_hex="1",
        cipher_hex="2",
    )

    class FakeRequestor:
        def request_tgs(self, spn, use_rc4=False):
            return material

    harvester = kerberoast_module.KerberosHarvester(FakeRequestor())
    result = harvester.roast("cifs/h", use_rc4=True)
    assert result == material


def test_harvester_roast_all_fans_out_over_spns(kerberoast_module):
    material = kerberoast_module.Krb5TgsMaterial(
        user="u",
        realm="CORP.LOCAL",
        spn="S",
        etype=18,
        checksum_hex="7",
        cipher_hex="8",
    )

    class FakeRequestor:
        def request_tgs(self, spn, use_rc4=False):
            return material

    harvester = kerberoast_module.KerberosHarvester(FakeRequestor())
    accounts = [
        kerberoast_module.SpnAccount(
            sam="svc-sql",
            sid=None,
            tier=1,
            tier_label="tier1",
            spns=("cifs/a", "http/b"),
            uac=0x200,
            uac_flags=(),
        ),
    ]
    results = harvester.roast_all(accounts)
    assert len(results) == 2


def test_harvester_roast_without_requestor_raises(kerberoast_module):
    harvester = kerberoast_module.KerberosHarvester(None)
    try:
        harvester.roast("cifs/x")
    except kerberoast_module.KerberoastError as exc:
        assert "--user" in str(exc)
        return
    raise AssertionError("expected KerberoastError")


def test_harvester_discover_mock(kerberoast_module):
    accounts = kerberoast_module.KerberosHarvester(None).discover(
        None, "DC=corp,DC=local", mock=True
    )
    assert len(accounts) == 5


def test_kdc_error_maps_to_wrapped_kds_error(kerberoast_module):
    err = kerberoast_module._kdc_error(RuntimeError("KDC_ERR_PREAUTH_REQUIRED message"))
    assert isinstance(err, kerberoast_module.KdsError)
    assert "KDC_ERR_PREAUTH_REQUIRED" in str(err)


def test_call_impacket_kwargs_fallback(kerberoast_module):
    def fn(a=1, b=2):
        return a + b

    assert kerberoast_module._call_impacket(fn, [], a=3, b=4, unknown=9) == 7


def test_kerberoast_discover_cli_mock(kerberoast_module):
    assert kerberoast_module._main(["discover", "--mock"]) == 0
