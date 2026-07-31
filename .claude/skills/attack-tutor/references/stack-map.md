# The user's stack, mapped to ATT&CK

Read this when scoping to one platform, or when the user asks "what matters for my cloud app /
my Kubernetes cluster / our SSO". All figures come from `attack.py` against the current
dataset — regenerate rather than trusting these numbers indefinitely.

The full default scope is **581 of 697 techniques**. Broken down, each slice is much smaller and
much more learnable.

---

## Identity Provider — 48 techniques

**The smallest surface and the most important one.** Entra ID, Okta, Ping, federation, OAuth.

Start the user here. Identity is where application attacks now begin, and the technique count is
small enough to genuinely learn in full.

Top techniques by real-world use:

| ID | Technique | Groups |
|---|---|---|
| T1078 | Valid Accounts | 56 |
| T1566.002 | Spearphishing Link | 55 |
| T1189 | Drive-by Compromise | 34 |
| T1110 | Brute Force | 17 |
| T1078.004 | Cloud Accounts | 13 |
| T1110.003 | Password Spraying | 13 |
| T1199 | Trusted Relationship | 13 |

Highest-leverage controls: M1018 User Account Management (25), M1032 MFA (20), M1026 Privileged
Account Management (19), M1047 Audit (17).

**The architect's lesson here.** Almost everything routes through T1078 Valid Accounts — the
adversary logging in rather than breaking in. There is no exploit, no malware, nothing for an
endpoint agent to catch. The controls are all design-time: which identities exist, what they can
do, how they authenticate, whether the session can be stolen after login. Note that MFA does not
address T1539 Steal Web Session Cookie — the token is taken *after* authentication succeeds.
Session binding is a separate decision.

T1199 Trusted Relationship is the one architects most often miss: your identity trust extends to
suppliers, contractors and federated tenants, and it is inherited whole.

---

## IaaS — 104 techniques

AWS, Azure, GCP workloads, instances, storage, roles.

| ID | Technique | Groups |
|---|---|---|
| T1082 | System Information Discovery | 71 |
| T1190 | Exploit Public-Facing Application | 65 |
| T1078 | Valid Accounts | 56 |
| T1685 | Disable or Modify Tools | 41 |
| T1046 | Network Service Discovery | 38 |
| T1049 | System Network Connections Discovery | 37 |
| T1119 | Automated Collection | 27 |

Highest-leverage controls: M1018 (48), M1047 Audit (29), M1026 (23), M1032 MFA (23).

**The architect's lesson.** Two entry doors — exploit the exposed app (T1190) or use valid
credentials (T1078) — then a lot of discovery. Discovery techniques rank high because cloud
control planes are extremely talkative: one API call enumerates the estate. The instance role or
managed identity attached to a workload is usually the real prize, so blast-radius design (what
can this role reach?) does more than perimeter hardening.

T1685 Disable or Modify Tools at 41 groups is worth flagging: adversaries routinely turn off
logging and security tooling. If your audit trail can be disabled by the identity you are
auditing, it is not an audit trail. Design CloudTrail/Activity Log integrity as a separate
control.

---

## SaaS and Office Suite — 70 and 78 techniques

Microsoft 365, Google Workspace, Salesforce, and the integrations wired into them.

| ID | Technique | Groups |
|---|---|---|
| T1078 | Valid Accounts | 56 |
| T1566.002 | Spearphishing Link | 55 |
| T1119 | Automated Collection | 27 |
| T1684.001 | Impersonation | 18 |
| T1110 | Brute Force | 17 |
| T1114.002 | Remote Email Collection | 16 |
| T1657 | Financial Theft | 16 |

**The architect's lesson.** This is where business-impact attacks land — T1657 Financial Theft
appears directly, which is unusual for ATT&CK and tells you what these intrusions are actually
for. The recurring architectural failure is OAuth application consent: a user grants a malicious
third-party app persistent mailbox access, and it survives every password reset because it never
used a password. If your project integrates with a SaaS tenant, who can consent to apps is a
design decision you own.

---

## Containers — 48 techniques

Docker, Kubernetes, orchestration.

| ID | Technique | Groups |
|---|---|---|
| T1036.005 | Match Legitimate Resource Name or Location | 76 |
| T1190 | Exploit Public-Facing Application | 65 |
| T1078 | Valid Accounts | 56 |
| T1685 | Disable or Modify Tools | 41 |
| T1046 | Network Service Discovery | 38 |
| T1133 | External Remote Services | 38 |
| T1068 | Exploitation for Privilege Escalation | 24 |

Highest-leverage controls: M1018 (21), M1026 (18), M1047 Audit (15), M1038 Execution Prevention (10).

**The architect's lesson.** T1036.005 at the top is the supply-chain story: an image named to
look legitimate. Registry provenance and admission control are architecture decisions, not
runtime ones. After that it is the classic container chain — exploit the workload, then escape
or pivot via the service account. The Kubernetes service account token mounted into every pod by
default is the most commonly overlooked credential in the whole stack.

Note the small count (48). Containers are well-covered by ATT&CK relative to their size, so this
is a realistic slice to learn completely.

---

## Linux and Windows servers — 355 and 474 techniques

The hosts underneath everything.

**Deliberately deprioritised for this user.** This is the bulk of the catalogue and the least
relevant to an application architect: most of it is endpoint and workstation tradecraft owned by
the platform and detection teams, not by application design.

Teach from here only when the user asks, or when a technique in their scope happens to live
here. The parts that genuinely matter to application design:

- **T1505.003 Web Shell** — the classic persistence after T1190, and directly your problem
- **T1053 Scheduled Task/Job** — persistence via cron/systemd on application servers
- **T1543 Create or Modify System Process** — service-level persistence
- **T1552 Unsecured Credentials** — secrets in config files, environment variables, source; an
  application design failure, not a platform one

Do not walk the user through PowerShell tradecraft or LSASS credential dumping unless they ask.
It is real, it is well-documented, and it is somebody else's job.

---

## Suggested teaching order

1. **Identity Provider** — smallest, highest leverage, where their applications actually get hit
2. **The T1078 → T1190 pair** — the two doors, and the difference between logging in and breaking in
3. **IaaS** — the cloud control plane and blast radius
4. **Containers** — if their projects use them
5. **SaaS/Office Suite** — if their projects integrate with a tenant
6. **Servers** — only the four application-relevant techniques above, on demand
