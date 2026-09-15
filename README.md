# AD Threat Lab — Enterprise Active Directory Attack Simulation & Detection Lab

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
> **Status:** Production Release `v1.0.0` (Automated Multi-VM ATT&CK Simulation & Detection)

> **Status:** Production Release `v1.0.0` (Automated Multi-VM ATT&CK Simulation & Detection)

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](requirements.txt)
[![CI](https://github.com/DarcHacker/ad-threat-lab/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Navigator-red.svg)](https://attack.mitre.org/matrices/enterprise/)

Enterprise Active Directory attack simulation sandbox — automated provisioning, multi-stage MITRE ATT&CK attack paths, custom Python abuse tooling, and production Sigma detection engineering.

**Author:** Mostafa Ibrahim (DarcHacker) — License: MIT

---

## Table of Contents

1. [Architecture](#architecture)
2. [Attack Paths (MITRE ATT&CK)](#attack-paths-mitre-attck)
3. [Quickstart](#quickstart)
4. [Lab Configuration](#lab-configuration)
5. [Custom Tooling](#custom-tooling)
6. [Playbooks](#playbooks)
7. [Detection Engineering](#detection-engineering)
8. [Detection Triage](#detection-triage)
9. [Testing & CI](#testing--ci)
10. [Cleanup / State Reset](#cleanup--state-reset)

---

## Architecture

3-Tier Enterprise Lab: Domain Controller, joined Workstation, and Attacker/Audit host. A "Tiered Administration" model (Tier-0/1/2 per Microsoft's Enterprise Access Model) is enforced so that every attack path is mapped against a *privilege boundary*, exactly like a real enterprise environment.

```
                                         ┌──────────────────────────────────────────────────────────────┐
                                         │                        LAB NETWORK (192.168.56.0/24)           │
                                         └──────────────────────────────────────────────────────────────┘
        ┌───────────────────────┐        ┌──────────────────────┐        ┌───────────────────────┐
        │        DC01           │        │         WS01         │        │      UBUNTU-SEC       │
        │  Windows Server 2022  │        │    Windows 11 / 10   │        │   Ubuntu 22.04 LTS    │
        │  CORP.LOCAL forest    │        │  CORP\ws01$ machine  │        │   Attacker / Audit    │
        │  AD DS + DNS + CA     │        │  Tier-1/2 workloads  │        │   host for offensive   │
        │  Tier-0 store         │        │  (no DC roles)       │        │   & validation tooling │
        └───────────┬───────────┘        └──────────┬───────────┘        └───────────┬───────────┘
                    │                               │                               │
       192.168.56.10│               192.168.56.20   │               192.168.56.30   │
        CORP.LOCAL  │                 ws01.corp.local   │            ubuntu-sec.corp.local
        └───────────┴───────────────────────────────┴───────────────────────────────┘
                                                                        │
                                                   Impacket · BloodHound · Rubeus ·
                                                   Mimikatz · Certipy · ldap3 tools
```

| Host | Role | OS | Address |
|------|------|----|---------|
| **DC01** | Domain Controller (AD DS, DNS, optional AD CS) | Windows Server 2022 | `192.168.56.10` |
| **WS01** | Domain-joined workstation (attack destination) | Windows 11 | `192.168.56.20` |
| **UBUNTU-SEC** | Attacker / Audit host | Ubuntu 22.04 | `192.168.56.30` |

---

## Attack Paths (MITRE ATT&CK)

Every attack path is reproduced against the lab's tiered object model. The table below maps **kill-chain stage → technique → toolset → underlying misconfiguration** so detection teams can go straight from alert to lab reproduction.

| # | Kill-Chain Stage | ATT&CK Technique | Tooling | Lab Misconfiguration | Playbook |
|---|------------------|------------------|---------|----------------------|----------|
| 1 | Recon | T1018 Remote System Discovery / T1087 Account Discovery | BloodHound, `ldapdomaindump`, `spn_collector.py` | Baseline domain (no misconfig needed) | `01_recon_and_bloodhound.md` |
| 2 | Credential Access | **T1558.004 AS-REP Roasting** | Rubeus, impacket `GetNPUsers.py` | Pre-auth not required on `corp\asrep_user` | `02_kerberos_attacks.md` |
| 3 | Credential Access | **T1558.003 Kerberoasting** (RC4 vs AES) | Rubeus, `GetUserSPNs.py`, `py_kerberoast.py` | SPNs on Tier-0 service accounts | `02_kerberos_attacks.md` |
| 4 | Credential Access / Lateral | **T1557.001/T1187 Coerced Auth + T1558 ADCS** | PetitPotam, ntlmrelayx, Certipy (ESC8 HTTP relay) | AD CS web enrollment without NTLM-relay hardening | `03_ntlm_relay_and_adcs.md` |
| 5 | Privilege Escalation | **T1548/T1222 ACL Abuse** (GenericAll, WriteDacl, ForceChangePassword, RBCD) | BloodHound pathfinding, `acl_scanner.py`, impacket `addcomputer.py` | Insecure DACLs defined in `vulnerable-acls.json` | `04_acl_abuse_and_privesc.md` |
| 6 | Persistence | **T1098.002 Account Manipulation / T1558.001 Golden Ticket** | Modify SPNs, `rubeus dump`/`forge`, Mimikatz `kerberos::golden`, secretsdump | DCSync on backup account; weak krbtgt key handling | `05_persistence_and_tickets.md` |

---

## Quickstart

### 1. Clone & validate tooling

```bash
git clone https://github.com/DarcHacker/ad-threat-lab.git
cd ad-threat-lab
make setup            # python -m venv .venv && pip install -r requirements.txt
make scan-syntax     # compile-check every Python tool + PowerShell syntax check (pwsh)
make lint             # ruff check tools tests
```

### 2. Stand up the 3-tier lab

```bash
vagrant up            # provisions DC01 (forest), WS01 (join), UBUNTU-SEC (tools)
vagrant provision dc01 --provision-with shell     # re-run domain setup if interrupted
```

`provision.ps1` builds the forest, OUs, tiered users and groups. `inject_misconfigs.ps1` then
injects the vulnerable state (SPNs, AS-REP user, ADCS, delegation), and `cleanup.ps1` reverts it.

### 3. Hunt without a domain (offline / CI)

Every custom tool works **fully offline against mock data**:

```bash
python -m tools.spn_collector --mock              # synthetic users + SPNs, ranked by privilege
python -m tools.acl_scanner --sd-b64 ...          # parse a raw NT Security Descriptor blob
python -m tools.py_kerberoast --mock-cert TGS...  # build $krb5tgs$ hashes from test fixtures
```

This keeps CI hermetic: unit tests never touch a live domain.

### 4. Run the full suite

```bash
make test        # pytest -q
make lint        # ruff check tools tests
make format      # ruff format tools tests
```

---

## Lab Configuration

| File | Purpose |
|------|---------|
| `configs/lab-config.json` | CORP.LOCAL schema: OUs (Tier-0/1/2, Service Accounts, Privileged Access), tiered users & groups, high-value targets, SPN list, delegation accounts |
| `configs/vulnerable-acls.json` | Insecure DACL catalog: `GenericAll`, `WriteDacl`, `ForceChangePassword`, `RBCD` (AllowedToAct) — consumed by `inject_misconfigs.ps1` and validated by `tests/test_configs.py` |

The provisioning + injection scripts read this JSON contract, so the **state of the lab is always reproducible and the ACL catalog is machine-checkable**.

---

## Custom Tooling

Pure-Python 3.11+ tooling (ldap3 + impacket) — no placeholders, full type-hints, `argparse` CLI, clean exception handling.

| Tool | What it does | Offline mode |
|------|--------------|--------------|
| `tools/spn_collector.py` | Non-intrusive LDAP SPN harvesting with privilege ranking (Tier-0 vs Tier-1/2 based on group membership) | `--mock` |
| `tools/py_kerberoast.py` | Pure-Python SPN discovery + TGS request → `$krb5tgs$23$*` hash extractor (RC4/AES cipher selection) | `--mock-discovery` / hash builder unit-tested |
| `tools/acl_scanner.py` | Parses raw NT Security Descriptors over LDAP, flags `GenericAll` / `WriteDacl` / `WriteOwner` / `GenericWrite` / `ForceChangePassword` / `AllowedToAct` (RBCD) | `--sd-b64`, `--sddl` |

---

## Playbooks

Step-by-step offensive walkthroughs with **exact commands** and the **"Why / How / Defensive Artifact"** structure:

- `01_recon_and_bloodhound.md` — LDAP queries, BloodHound ingestors, attack path discovery
- `02_kerberos_attacks.md` — AS-REP Roasting, Kerberoasting (RC4 vs AES), ticket cracking
- `03_ntlm_relay_and_adcs.md` — Coerced auth (PetitPotam/PrinterBug) + ADCS ESC8 HTTP relay
- `04_acl_abuse_and_privesc.md` — GenericAll takeover, WriteDacl weaponization, RBCD execution
- `05_persistence_and_tickets.md` — DCSync (DS-Replication-Get-Changes), Golden/Silver Ticket forging

---

## Detection Engineering

| Artifact | Contents |
|----------|----------|
| `detections/sigma_rules.yaml` | Concrete Sigma rules: **Event 4769** (RC4 service-ticket downgrade), **Event 4624** (Type-3 network logon), **Event 4672** (special privileges assigned), **Event 5136** (directory object modified → ACL/delegation/SPN changes) |
| `detections/mitigation_matrix.md` | PAW/Tiering model, gMSA transition, GPO hardening, PAC/RBCD validation, detection tuning notes |

---

## Detection Triage

When a Sigma rule fires in the lab, trace it back through the full chain:

1. **Which event did you see?** 4769 RC4 → suspect Kerberoasting; 5136 on `msDS-AllowedToActOnBehalfOfOtherIdentity` → RBCD; 4624 Type-3 from `UBUNTU-SEC` → lateral movement or relay.
2. **Verify the primitive existed.** Confirm the corresponding misconfig in `configs/vulnerable-acls.json` or SPN list in `lab-config.json` was injected.
3. **Replay in isolation.** Run the playbook command against a fresh clone of the vulnerable object.
4. **Harden then re-triage.** Apply the matching control from `mitigation_matrix.md`, revert the lab (`cleanup.ps1`), re-run — the event must disappear.
5. **Tune the rule.** Adjust `detection` filters in `sigma_rules.yaml`, not the threshold, until True Positive rate holds.

---

## Testing & CI

- `tests/test_configs.py` — JSON schema + referential-integrity validation of both config catalogs.
- `tests/test_tools.py` — unit tests for the three Python tools against **mock LDAP / Kerberos / Security-Descriptor** fixtures (no live domain required).
- `.github/workflows/ci.yml` — runs `pytest`, `ruff lint`, and JSON schema validation on every push/PR.

---

## Cleanup / State Reset

```powershell
# On DC01, from the automation/ directory:
.\cleanup.ps1 -ResetLab                         # removes injected SPNs, resets pre-auth + delegation bits,
                                                # disables ADCS web enrollment, reverts ACL changes
.\inject_misconfigs.ps1 -ConfigJson ..\configs\vulnerable-acls.json   # re-inject a fresh vulnerable state
```

To destroy the entire environment: `vagrant destroy -f`.

---

> **USE RESPONSIBLY.** This repository is an **authorized testing lab** only. See [DISCLAIMER.md](DISCLAIMER.md).