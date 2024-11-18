# Playbook 01 — Recon & BloodHound: LDAP Queries, Ingestors, Attack-Path Discovery

> **Stage:** Recon (MITRE TA0043 / T1018, T1087)
> **Toolset:** `ldapsearch`, `ldapdomaindump`, BloodHound + SharpHound, `tools/spn_collector.py`
> **Gol with this environment:** Inventory every identity/Tier object, seed BloodHound's
> graph, and tease out the shortest Tier-2 → Tier-0 paths that the next playbooks execute.

---

## 1. Why

Recon in a domain is not "port scanning AD". Active Directory is a *graph of
privilege*: users → groups → GPOs → computers → ACLs → certificates. Every one
of the attacks in playbooks 02–05 becomes possible because recon first answered
**who has which SPN (Kerberoast surface)**, **who holds which right to which
object (ACL surface)**, and **where do high-value users sit in the graph
(attack-path surface)**.

The lab enforces a Tiered Administration (Tier-0/1/2) model so recon results are
directly comparable to an enterprise: a standard Tier-2 user (`t2-user`) should
*not* own rights to Tier-1 groups — when the graph says otherwise, playbook 04
likely has a path.

## 2. Phase A — Unauthenticated LDAP fingerprinting (non-intrusive)

From `UBUNTU-SEC`:

```bash
# 1. Directory enum basics
ldapsearch -x -H ldap://dc01.corp.local -b "DC=corp,DC=local" \
  -s base "(objectClass=*)" defaultNamingContext dnsRoot

# 2. Users with SPNs — this is the Kerberoasting prey (read-only!).
ldapsearch -x -H ldap://dc01.corp.local -b "DC=corp,DC=local" \
  "(&(objectClass=user)(servicePrincipalName=*))" \
  sAMAccountName servicePrincipalName objectSid memberOf

# 3. Full domain dump (ldapdomaindump maintains a browsable HTML corpus).
ldapdomaindump ldap://192.168.56.10 -u 'CORP\t2-user' -p 'LabStart!22445'
```

### Why these work
Anonymous base-bind is usually blocked on hardened DCs, but the *search filter
craft* is the real lesson: any authenticated directory reader can enumerate the
SPN surface — no LDAP-admin rights are needed. `servicePrincipalName=*` is the
single highest-yield filter in Windows recon.

## 3. Phase B — Non-intrusive harvesting with the lab's own tooling

The repo ships a purpose-built non-intrusive harvester that **ranks the SPN
surface by tier** so you know *which* accounts deserve an RC4 roast:

```bash
python -m tools.spn_collector --server 192.168.56.10 \
  --user 'CORP\t2-user' --password 'LabStart!22445' --format table --top 20
python -m tools.spn_collector --mock                     # offline parity check
```

### Ranking logic (the "privilege ranking" the tool names)
`rank_privilege()` in `tools/spn_collector.py` decodes each account's
`objectSid`, maps the last RID (512 Domain Admins, 519 Enterprise Admins,
544 BUILTIN\Administrators, 548 Account Operators, 551 Backup Operators) and
cross-checks `memberOf` group base-names. Tier-0 SPN accounts are the
**Critical** roast targets.

## 4. Phase C — BloodHound ingestion & attack-path discovery

### Ingestor — run as any user from a domain host (or via `--mock`)

```powershell
# On WS01 or from the UBUNTU-SEC host via SharpHound Linux:
SharpHound.exe --CollectionMethods All --ZipFileName corp_loot.zip
# or
python3 bloodhound-ng/BloodHound/Collectors/... # collect with cufflinks/recon
```

### Analysis (bloodhound-python or Neo4j GUI)

```python
# bloodhound-python from UBUNTU-SEC (graphs DACLs, memberships, RIDs):
bloodhound-python -u 't2-user' -p 'LabStart!22445' -d corp.local -ns 192.168.56.10 -c All
```

### Attack-path discovery
After `sharp-collect.zip` is uploaded to BloodHound:

1. **"Shortest Paths From Owned Principals"** – mark `t2-user` as owned;
   BloodHound will list every path to `Domain Admins`.
2. **"Shortest Paths to Domain Admins"** – reverse map which of *your* accounts
   are one hop from Tier-0.
3. **Kerberoastable Users** → rank column to re-confirm `svc-sql`.
4. **AS-REP Roastable Users** → should light up `asrep-user` (canary).

### Expected lab edges that prove the misconfigs took

| Edge | Meaning | Source object |
|------|---------|---------------|
| `t2-user → GenericAll → Tier1-Admins` | writable group membership | `vulnerable-acls.json` acl-001 |
| `t1-admin → WriteDacl → SQL-Admins` | DACL rewrite primitive | acl-002 |
| `k.salim → ForceChangePassword → darc-admin` | DA reset primitive | acl-003 |
| `svc-rbcd → AllowedToAct → DC01$` | RBCD path to DA | acl-004 |
| `svc-sql has SPN uid + Tier-1 group` | Kerberoast surface | lab-config spns |

## 5. Attribution & Defensive Artifacts

Every query you ran produced **directory reads** that a Detection Team can
observe:

| Event | Meaning | Rule |
|-------|---------|------|
| 2889 | **unsigned** LDAP BIND (channel-binding tattler) | mitigation matrix row 1 |
| 3169 | DC LDAP-see-session events when signing required fails | row 1 |
| 4662 | "Replicating Directory Changes" (on `spn_collector` it won't appear — non-replication read) | baseline |
| ADSI error codes in event 4624/4625 sequence during bind | enumeration burst | — |

BloodHound's exported `.json`/`.jsonl` corpus, the `ldapsearch` raw output, and
`spn_collector --json` capture form the **recon evidence archive** — attach it
to your final report; mitigations are in `detections/mitigation_matrix.md`.

---

## Theory — "Why BloodHound is a cheat code"

BloodHound compiles LDAP reads into a **graph of directed trust edges**. Two
edges — `WriteDacl` and `GenericAll` — are "shortcut" edges that compress a
many-hop path to a single step. When your Tier-2 account lights up a *red short
path* to `Domain Admins`, the lab's `inject_misconfigs.ps1` has delivered exactly
the enterprise shape the playbooks expect.