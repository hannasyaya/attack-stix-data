# The user's stack, mapped to ATT&CK

Read this when scoping to one platform, or when the user asks "what matters for my cloud app /
my Kubernetes cluster / our SSO". All figures come from `attack.py` against the current
dataset — regenerate rather than trusting these numbers indefinitely.

The full default scope is **581 of 697 techniques**. Broken down, each slice is much smaller and
much more learnable.

---

## Cloud reference: Azure

The user works in Azure. All cloud examples use Azure and Microsoft services. ATT&CK's data is
AWS-weighted, so translate — and say when you are translating.

| ATT&CK / AWS term | Azure equivalent |
|---|---|
| AWS account | Subscription (billing/isolation), tenant (identity), management group |
| IAM role / policy | Azure RBAC role assignment at a scope |
| EC2 instance profile / instance role | Managed identity (system- or user-assigned) |
| `AssumeRole` | Token from IMDS at `169.254.169.254`, or federated credential |
| AWS root user | No exact match. Nearest: Global Administrator in Entra ID, Owner at subscription or management-group scope, and break-glass accounts |
| S3 bucket | Storage account → blob container |
| Secrets Manager | Key Vault |
| Lambda | Azure Functions |
| EKS | AKS |
| ALB | Application Gateway / Front Door |
| Security Groups | NSG, or Azure Firewall |
| `AWS:CloudTrail` (142 analytics) | **Two separate logs**: Azure Activity Log for control-plane writes, Entra ID sign-in and audit logs for identity. This split has no AWS equivalent and is the most common translation mistake |
| `AWS:VPCFlowLogs` | NSG flow logs / VNet flow logs |
| `AWS:CloudWatch` | Azure Monitor, into a Log Analytics workspace |

**Azure log sources that genuinely appear in ATT&CK analytics** — safe to cite as ATT&CK's own:
`azure:signinlogs` (35), `azure:audit` (13), `azure:activity` (9), `azure:policy` (3),
`azure:ad`, `azure:vpcflow`, `azure:vmguest`, `ApplicationLog:EntraIDPortal`,
`Microsoft Entra ID Audit Logs`, plus the M365 family — `m365:unified` (88), `m365:exchange`,
`m365:signinlogs`, `m365:oauth`, `m365:defender`. For AKS, `kubernetes:audit` (12) and
`kubernetes:apiserver` (10) apply directly.

Anything else Azure-specific is your translation, not ATT&CK's. Label it as such.

**Two Azure-specific concerns ATT&CK covers poorly**, worth raising because they are design
decisions the user owns:

- **The Entra ID / Azure RBAC split.** Entra roles (Global Administrator) and Azure RBAC roles
  (Owner) are different systems with different escalation paths, and a Global Administrator can
  elevate to gain access to all subscriptions. ATT&CK's cloud model does not represent this
  cleanly.
- **Managed identity as the real prize.** Compromising a workload yields its managed identity
  with no credential to steal or rotate — the token comes from the instance metadata endpoint.
  This maps to T1078.004 Cloud Accounts, but the "no credential exists" property is what makes
  blast-radius design the only real control.

---

## Identity Provider — 48 techniques

**The smallest surface and the most important one.** Entra ID, federation, OAuth, Conditional
Access. (ATT&CK's analytics often name Okta as the example identity provider; the technique
applies identically to Entra ID.)

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

Azure subscriptions, VMs and VM Scale Sets, App Service, Storage accounts, managed identities,
Azure RBAC.

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
control planes are extremely talkative: one Azure Resource Graph query enumerates the estate,
and any authenticated principal can read far more of the directory than people expect. The
managed identity attached to a workload is usually the real prize, so blast-radius design (what
RBAC scope can this identity actually reach?) does more than perimeter hardening.

T1685 Disable or Modify Tools at 41 groups is worth flagging: adversaries routinely turn off
logging and security tooling. If your audit trail can be disabled by the identity you are
auditing, it is not an audit trail. In Azure that means diagnostic settings and the Log
Analytics workspace need their own RBAC boundary — an Owner on the subscription can otherwise
delete the evidence. Note also that Azure Activity Log retention defaults to 90 days unless you
export it.

---

## SaaS and Office Suite — 70 and 78 techniques

Microsoft 365 — Exchange Online, SharePoint, Teams — and the third-party apps wired into the
tenant. Well served by ATT&CK's data: `m365:unified` is the third most-referenced log source in
the whole catalogue at 88 analytics.

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
for. The recurring architectural failure is **OAuth application consent**: a user grants a
malicious third-party app `Mail.Read` on their behalf, and that access survives every password
reset and MFA prompt because it never used a password. In Entra ID this is user consent
settings and admin consent workflow — a tenant-level design decision you own. `m365:oauth` and
`m365:unified` carry the consent-grant events.

The Azure-specific escalation worth knowing: an application registration with a
**client secret** and Graph application permissions is a non-human identity with no MFA, no
Conditional Access by default, and a secret that often outlives the project that created it.

---

## Containers — 48 techniques

AKS, Azure Container Apps, Container Registry.

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
runtime ones — in Azure that means ACR content trust plus an admission policy that refuses
images from anywhere else. After that it is the classic container chain — exploit the workload,
then escape or pivot via the service account. The Kubernetes service account token mounted into
every pod by default is the most commonly overlooked credential in the whole stack.

On AKS specifically, the identity story is doubled: a pod may hold both a Kubernetes service
account token *and*, via workload identity federation, an Entra ID managed identity with Azure
RBAC. Compromising one pod can therefore cross out of the cluster into the subscription
entirely. Whether those two identity planes are allowed to connect is a design decision, and
it is the one most worth challenging in an AKS review.

`kubernetes:audit` and `kubernetes:apiserver` are real ATT&CK log sources and map directly to
AKS diagnostic settings.

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
