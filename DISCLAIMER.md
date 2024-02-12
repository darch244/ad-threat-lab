# DISCLAIMER & Authorized Security Testing Policy

This repository (`ad-threat-lab`) is an **authorized, self-contained attack simulation environment
intended exclusively for security research, detection-engineering validation, and training**.

## Authorized Use Only

- The lab runs **local, disposable virtual machines** in an isolated virtual network
  (`192.168.56.0/24`). No internet-facing services, no production systems, no third-party assets
  are ever touched by any script, playbook, or tool in this repository.
- You must **own the environment** or have **explicit written authorization** from its owner
  before running any tool, command, or playbook contained here against any computer system.
- All offensive techniques (Kerberoasting, AS-REP Roasting, NTLM relay, ADCS abuse, ACL abuse,
  DCSync, Golden/Silver Tickets, RBCD) are documented and implemented **solely for the purpose of
  validating the corresponding detections and mitigations** inside the lab.

## What This Lab Is

A **blue-team enablement asset**: each attack is paired with the precise defensive artifact it
produces (Event ID, Sigma rule, BloodHound edge, log field) and the mitigation that removes the
root cause (`detections/mitigation_matrix.md`).

## What This Lab Is NOT

- Not a toolkit for attacking systems you do not own or lack authorization to test.
- Not an excuse to run `DCSync`, `mimikatz`, or NTLM-relay tooling against production
  infrastructure. Doing so may constitute a criminal offense under applicable law
  (e.g., CFAA/US §1030, Computer Misuse Act 1990, §202 StGB, etc.).

## Your Responsibilities

1. Run everything inside the Vagrant-lab boundary described in `README.md`.
2. Treat captured credentials and materials as **secret and ephemeral** — explicitly an artifact
   of an already-compromised lab, to be destroyed with the environment.
3. Consent-free credential extraction, lateral movement, or data exfiltration against other
   parties is **always out of scope** and is not endorsed by this project in any form.

## No Warranty

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

**By using this repository you acknowledge that you are responsible for complying with all
applicable laws and for obtaining all necessary authorizations.**