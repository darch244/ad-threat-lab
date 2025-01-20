# Mitigation & Detection Matrix — CORP.LOCAL Lab

Controls are mapped **1:1 to the attack paths in `README.md`** and to the
events the lab's playbooks produce. The "Validate in lab" column links each
control to the exact off/on test: harden, `cleanup.ps1 -ResetLab`, re-run the
attack, and the corresponding `detections/sigma_rules.yaml` rule must go
silent.

| # | Attack path | Control / mitigation | Priority | Detect (event / rule) | Validate in lab |
|---|-------------|----------------------|----------|----------------------|-----------------|
| 1 | Recon via LDAP | Enforce LDAP channel binding + signing (GPO: `Domain controller: LDAP server signing requirements` = *Require*); conditional-access read on `ReadAccountRestrictions` for service accounts | High | 2889 (unsigned LDAP), 3169 | Run `spn_collector --server dc01` unauthenticated → must fail |
| 2 | AS-REP Roasting (T1558.004) | `Set-ADAccountControl` requires pre-auth on all accounts; automated audit queries `userAccountControl` for `0x400000` | High | 4768 (AS-REQ without pre-auth is not an alert in itself; correlate 4768 + 4771) | `GetUserSPNs`/Rubeus must return zero hashes |
| 3 | Kerberoasting (T1558.003) | 1) **gMSA transition** — convert batch/service accounts to `msDS-ManagedServiceAccount`; 2) **Strong SPN secrets** — password ≥ 48 chars & rotated every 30d; 3) disable RC4 via **Group Policy `Kerberos: Supported encryption types`**; 4) monitor Tier-0 SPN re-classification | Critical | 4769 `TicketEncryptionType=0x17`; logon type 3 on SPN service | Rule `5b3a0c2a` fires during `py_kerberoast --rc4`, silent after RC4 disabled |
| 4 | Coerced auth (PetitPotam / PrinterBug) (T1187/T1557) | Block SMB outbound from DCs to internet; disable `MSRPC` Printer Spooler via registry (`RpcAuthnLevelPrivacyEnabled`); firewall `135-139/445` | Critical | 4624 Type 3 from DC to workstation; SMB `\\host\IPC$` patterns via 5145/5140 | Coercion tooling must not reach `MOFUNC`/EFS endpoints on WS01 |
| 5 | ADCS ESC8 (NTLM relay to web enrollment) | Require **Extended Protection for Authentication (EPA)** on PKI web endpoints; restrict CertSrv HTTP enrollment to specific Tier-0 hosts; monitor `http.sys` 443 access | Critical | 4624 Type 3 → `/certsrv/certfnsh.asp`; IIS 3050 WS access log | `certipy auth` with relayed creds to CA must fail |
| 6 | GenericAll / WriteDacl ACL abuse (T1548.002/T1228) | Use **PAW/Tiering model**: Tier-0 objects are only writable from Tier-0 PAWs; disable ACL-modification rights on `Domain Admins`, `Allowed To Act`; audit `WriteDacl` on sensitive groups | Critical | 5136 `msFSMO-...`/`nTSecurityDescriptor` writes; 5137/4742 | `acl_scanner --server dc01` lists no `GenericAll`/`WriteDacl` ACEs targeting privileged groups |
| 7 | ForceChangePassword (T1098) | Explicit `User-Force-Change-Password` extended-right grants only to Tier-0 PAW identities; block self-service reset on DA | High | 4768/4738 correlated with the control-access GUID `00299570-246d-11d0-a768-00aa006e0529` | `k.salim` resetting `darc-admin` must be logged as 4738 + password-changed |
| 8 | RBCD (T1558.002 / T1528) | Remove `msDS-AllowedToActOnBehalfOfOtherIdentity` values; monitor **all** writes to that attribute; disable `Resource-Based Constrained Delegation` on Tier-0 computers | Critical | 5136 `AttributeLDAPDisplayName=msDS-AllowedToActOnBehalfOfOtherIdentity` (rule `1b2a3c4d`) | `Get-ADComputer DC01` shows the attribute empty after `cleanup.ps1` |
| 9 | DCSync (T1003.006) | Remove `DS-Replication-Get-Changes*` from non-DC accounts; enable **Credential Guard** + LSA protection (`RunAsPPL`); rotate `krbtgt` twice after any DA compromise | Critical | 4662 (Replicating Directory Changes), 4769, `secretsdump` NTDS.dit reads | `secretsdump` from `backup-op` must fail after removing the extended right |
| 10 | Golden / Silver Ticket (T1558.001) | Rotate `krbtgt` and per-service `-Password` on a 120-day cadence; enable **PAC validation** (`ValidateKdcPacSignature` / sequential PAC checks on DCs); ticket lifetimes 10h/7d | Critical | 4768/4769 with forged `KRBTGT` principal; 4771 | After simulating a golden ticket, the PAC-signature validator must log 4771 |
| 11 | Lateral movement SMB (T1021.002) | Restrict SMB admin shares (`$ipc$`) to Tier-0; enable SMB signing (`Require`) | High | 4624 Type 3 `NtLmSsp`, then 5140/5145 admin-share access | `smbclient //dc01/admin$` fails after GPO `Microsoft network server: Digitally sign communications` |

## PAW / Tiering Model

```
               ┌──────────────────────────────┐
               │        TIER 0 (DC / PAW)     │  darc-admin, k.salim, DA/EA/BA
               └──────────────┬───────────────┘
                        protected (no web, no email)
               ┌──────────────┴───────────────┐
               │        TIER 1 (servers)      │  svc-sql, svc-httpd, t1-admin
               └──────────────┬───────────────┘
               ┌──────────────┴───────────────┐
               │        TIER 2 (workstations) │  t2-user, asrep-user
               └──────────────────────────────┘
```

* Only **designated PAW credentials** may administer Tier-0 objects — the ACL
  primitives in `vulnerable-acls.json` violate this by design so detections can
  be graded.
* gMSA transition applies to all service accounts (`svc-*`); the playbooks keep
  SPN-based accounts deliberately to produce Kerberoast material.

## gMSA Transition Recipe

```powershell
# 1. Provide a domain administrator whose key-distribution swap is allowed:
Add-KdsRootKey -EffectiveImmediately
# 2. Create/adopt the service account as agmsa:
New-ADServiceAccount -Name 'gmsa-sql' -DNSHostName 'gmsa-sql.corp.local' `
  -ServicePrincipalNames 'MSSQLSvc/sql01.corp.local:1433' -ManagedPasswordIntervalInDays 30
# 3. Register on the consuming host and disable the legacy SPN repository:
Install-ADServiceAccount -Identity 'gmsa-sql'
Set-ADUser svc-sql -ServicePrincipalNames @{Remove='MSSQLSvc/sql01.corp.local:1433'}
```

## GPO Hardening (minimum viable)

| GPO | Setting | Blocks |
|-----|---------|--------|
| Kerberos Policy | Maximum lifetime: 10h; renewal 7d | Golden/Silver ticket window |
| `Kerberos: Supported encryption types` | Remove RC4_HMAC_MD5 | Kerberoast RC4 downgrade |
| `Domain controller: LDAP server signing requirements` | Require signing | LDAP relaying/anonymous read |
| `Network security: Do not store LAN Manager hash` | Enabled | Credential offline cracking (partially) |
| `Microsoft network server: Digitally sign communications` | Required | SMB relay / MITM |
| Certificate Services | **Enable EPA** on `CertSrv` + `CertEnroll` sites | ADCS ESC8 relay |

## PAC Validation

Validating the PAC is a two-layer control:

1. **DC-side signature check** — `KERB_AP_OPTIONS` final-ticket PAC must be
   signed by the `krbtgt` account's key ring; a forged SHA-512 PAC is rejected.
2. **Application-server sequential check** — request the ticket's PAC, verify
   the `KDC` field is non-empty and the signature validates with
   `VerifyKrb5U2USelf`.

With both enabled, `mimikatz kerberos::golden` output produces `4771 KDC_ERR_BAD_OPTION`
events that `detections/sigma_rules.yaml` (4768 + 4771 correlation) catches.

## Detection Tuning Notes (production)

* Don't alert on `TicketEncryptionType=0x17` per se — send Tier-0 SPN targets to
  a **quarantine queue** and require a human to review them.
* 5136 writes are noisy; base-rate by `OperationType` and alert only on
  `AttributeLDAPDisplayName` changes to the three sensitive attributes with
  `SubjectUserName != Domain Controllers$`.
* Keep detection latency under 60s: forward 4769/4624/4672/5136 directly from
  `dc01` to the SIEM collectd pipeline; use Windows Defender ATP or a cheap
  Auditpol baseline otherwise.
* Logs must survive attacker post-exploitation: archive `Security.evtx`
  (Event ID 1102 flush + copy) or stream to syslog with
  `W32Time /TestIPv6`-fixed clock skew.