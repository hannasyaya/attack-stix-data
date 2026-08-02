# ATT&CK learning progress

The tutor reads this at the start of a session and updates it as you go. You can edit it freely.

**Role context:** security architect working in **application security** — designing security
solutions and controls into application projects. Learning ATT&CK to justify controls, specify
telemetry, and pressure-test designs. Not a detection engineer, and **not responsible for
platform or infrastructure security** — domain controllers, AD FS/AD CS, Exchange, VPN and
network appliances and endpoint tradecraft are other teams' remit and are out of scope.

**Stack scope:** Cloud (IaaS/SaaS), Identity Provider, Containers, Linux/Windows servers.
581 of 697 Enterprise techniques are in scope.

**Cloud reference: Azure.** Examples use Entra ID, subscriptions, managed identities, Azure
RBAC, Key Vault, App Service, AKS and Microsoft 365 — not AWS. Note that ATT&CK's own data is
AWS-weighted, so the tutor translates AWS log sources to their Azure equivalents and flags when
it is doing so.

---

## Status

**8 techniques covered** — one complete intrusion chain, end to end, taught 2026-07-31:

> T1190 / T1078 (get in) → T1078.001, T1078.004 (authenticate) → T1098 (stay) →
> T1530 (take) → T1567 (send) → T1486 (destroy)

**15 techniques covered.** Chain 1 completed 2026-08-01 — seven more techniques, spine APT29:

> T1199 → T1621 → T1556.007 → T1649 → T1098.005 → T1685.002 → T1114.002

**Next: three more chains**, each with a different shape, before applying any of this to a real
project. Chains are derived from real threat groups rather than narrated — pulling a named
group's techniques and ordering them by tactic gives an evidence-backed path.

1. ~~**Identity control subversion** (spine: APT29)~~ — **done 2026-08-01**. Attackers
   corrupting federation trust and the certificate authority rather than evading controls
2. **Business email compromise** — same identity substrate, completely different endgame
   (a payment, not encryption) ← **next**
3. **Container / AKS escape** — identity inherited rather than stolen
4. **Supply chain / CI-CD** — compromise at build time, upstream of every runtime control

Then a real Azure design with the `attack-threat-model` skill.

## Suggested route

Ordered smallest and highest-leverage first, not by ID. Rationale in
`.claude/skills/attack-tutor/references/stack-map.md`.

1. **Identity Provider** (48 techniques) — where application attacks actually begin, and small
   enough to learn completely
2. **The two doors** — T1078 Valid Accounts vs T1190 Exploit Public-Facing Application: logging
   in versus breaking in
3. **IaaS** (104) — cloud control plane, instance roles, blast radius
4. **Containers** (48) — image provenance, service account tokens, escape
5. **SaaS / Office Suite** (70/78) — OAuth consent, mailbox access, financial theft
6. **Servers** — only the four application-relevant techniques, on demand

## First block: identity

The techniques adversaries most often use against identity providers, most-used first. The
"groups" number is how many named threat groups and campaigns have been observed using it.

| # | ID | Technique | Groups | Done |
|---|---|---|---|---|
| 1 | T1078 | Valid Accounts | 56 | ☑ |
| 2 | T1566.002 | Spearphishing Link | 55 | ☐ |
| 3 | T1189 | Drive-by Compromise | 34 | ☐ |
| 4 | T1110 | Brute Force | 17 | ☐ |
| 5 | T1078.004 | Cloud Accounts | 13 | ☑ |
| 6 | T1110.003 | Password Spraying | 13 | ☐ |
| 7 | T1199 | Trusted Relationship | 13 | ☐ |

## Covered

### 2026-07-31 — the identity chain

Taught as a connected chain rather than as separate entries. The thread: **get in → authenticate
→ stay**.

**T1078 Valid Accounts** (56 groups) — the attacker signs in rather than breaking in. Sits under
four tactics at once, which is what makes it the most-used technique against cloud and identity.
Eight mitigations, all design-time. Key gap: MFA does nothing against session/token theft
(T1539), which happens after authentication succeeds.

**T1078.001 Default Accounts** (5 groups) — accounts that shipped with the system. Only two
mitigations because it is a build-time problem, not a runtime one. Azure has no single AWS-style
root user; the privilege is split across Entra ID roles and Azure RBAC, which makes it easier to
believe it is covered when it is not. Watch: AKS default service account token, the original
Global Administrator, break-glass accounts excluded from Conditional Access by design.

**T1078.004 Cloud Accounts** (13 groups) — cloud-only, no host involved. Three routes: user
account, service principal with a client secret, and hybrid identity via Entra Connect. The
presence of M1015 Active Directory Configuration on a "cloud" technique is ATT&CK saying the
on-prem/cloud boundary is not a boundary. Roster is the notable one: APT29/SolarWinds (forged
SAML), Scattered Spider and LAPSUS$ (help-desk social engineering), Storm-0501 (on-prem AD →
Entra ID pivot). Lesson: the account recovery process is a security control.

**T1098 Account Manipulation** (5 groups) — persistence and privilege escalation only;
presupposes access. This is why password resets fail to evict an attacker. Azure-relevant
sub-techniques: T1098.001 Additional Cloud Credentials (a second client secret on an existing
service principal), T1098.003 Additional Cloud Roles, T1098.005 Device Registration (registering
a device to *satisfy* Conditional Access), T1098.002 mailbox delegation. Prevention is weak by
nature — the attacker uses legitimate functionality with legitimate permissions — so this is a
detection-and-response requirement, and saying so is more honest than claiming a control.

**Cheap high-signal alert set identified:** credential additions and role assignments in the
tenant — `Microsoft.Authorization/roleAssignments/write` in the Activity Log, plus Entra audit
events for *Add service principal credentials*, *Add member to role*, *Add registered device*.
Export beyond the 90-day default.

### 2026-07-31 (later) — completing the chain

Four more techniques, chosen to close the loop rather than deepen identity: both entry doors,
then what the attacker came for.

**T1190 Exploit Public-Facing Application** (65 groups — second-highest in the catalogue) —
crafted input to something exposed, giving code execution. Single tactic: initial access. The
key link: your workload runs with a managed identity, so the attacker's first move is to ask
the instance metadata endpoint (`169.254.169.254`) for a token. ATT&CK's own container analytic
names that endpoint as an objective. **So T1190 is how attackers arrive at T1078.004** — they
inherit a credential rather than stealing one. Of the 8 mitigations only M1051 Update Software
actually prevents it; the rest limit blast radius. Cheap high-signal alert: an application
container spawning a shell, which it should never do.

**T1530 Data from Cloud Storage** (7 groups) — the structural point, and the most important one
for an application architect: ATT&CK notes there is often *no application* mediating access to
object storage; data is retrieved directly through the cloud API. **Your app is not in the
path**, so app-layer authorisation, rate limiting and audit logging are bypassed rather than
defeated. Data protection has to live at the storage layer. Two Azure specifics: blob
**data-plane logging is off by default** (Activity Log covers the control plane only), and
"encrypted at rest" is worth nothing here because the service decrypts transparently for any
authorised caller. Same actor roster as the persistence techniques — Scattered Spider,
Storm-0501, HAFNIUM — which is what they were persisting *for*.

**T1567 Exfiltration Over Web Service** (parent 8 groups, but T1567.002 shows 28) — upload to a
legitimate service because the traffic blends in, **the firewall already permits it**, and TLS
hides the contents. Only 2 mitigations, which is ATT&CK saying this cannot be reliably
prevented. Default-deny egress with an FQDN allowlist is the one control that would have
stopped it, and it is usually missing because it is operationally painful. Detection signal is
the outbound-to-inbound data ratio inverting. Reading note: when sub-techniques are heavily
used, read their counts, not the parent's.

**T1486 Data Encrypted for Impact** (22 groups — highest in impact) — the ransomware endgame.
Only 2 mitigations, and M1053 Data Backup only counts **if the compromised identity cannot
reach the backup**. By this stage the attacker holds Global Administrator or subscription
Owner, so if that identity can purge the vault, the backup is inside the blast radius rather
than outside it. This is why T1490 Inhibit System Recovery exists as a companion — they delete
recovery options first, then encrypt. Practical consequence: **recovery-inhibition alerts fire
early enough to act on; encryption alerts do not.** Also note the two variants that skip the
endpoint entirely — encrypting hypervisor datastores, and control-plane abuse of storage keys.

### The cross-cutting finding

Counting preventive mitigations along the chain: T1190 has 8, T1078 has 8, T1098 has 7 (and
weak), T1530 has 6, T1567 has 2, T1486 has 2.

**Preventive controls collapse as the attacker advances.** Design effort belongs at the left of
that sequence — patching, identity scope, blast radius — because by the right-hand end almost
nothing is left, and the one control that still works depends on an identity boundary decided
several steps earlier. This is the most useful strategic conclusion so far.

### 2026-08-01 — Chain 1: identity control subversion (spine: APT29)

Seven techniques, taught one per message in the full contract. Technique list derived from
APT29's own `uses` relationships in the bundle, not from memory — a planning assumption that
APT29 tampers with Conditional Access turned out to be **wrong** (that is Scattered Spider).
APT29 attacks the identity infrastructure itself.

**T1199 Trusted Relationship** (13 groups, TA0001 only) — entry inherited through a supplier,
contractor or federated tenant. Single tactic, which is the tell: it is a way in, nothing more.

**T1621 MFA Request Generation** (4 groups: APT29, C0027, LAPSUS$, Scattered Spider; TA0006) —
the user approves a prompt they did not initiate. MFA does not fail here, it is *granted*.
M1017/M1032/M1036. Signal: `azure:signinlogs` — repeated MFA challenges without a successful
primary login. The design answer is number matching, not more prompts.

**T1556.007 Hybrid Identity** (1 group) — **three tactics at once** (persistence,
credential-access, defence-impairment), which is the signature of a technique that corrupts a
trust foundation rather than defeating a control. APT29 edited the AD FS
`Microsoft.IdentityServer.Servicehost.exe.config` to load their own DLL into the authentication
process, gaining access to *"any service federated with AD FS"*. Only 3 mitigations. **The
Entra Connect / AD FS server is more privileged than everything it protects**, and is usually
administered as an ordinary Windows server — that is the gap.

**T1649 Steal or Forge Authentication Certificates** (1 group, TA0006) — APT29 abused
misconfigured **AD CS certificate templates** to impersonate admin users and mint *additional*
certificates: a credential factory, not a one-off theft. Certificates skip MFA, survive password
resets and last for years. Azure-native form: **a second certificate added to an app
registration** — rotating the original evicts nobody. M1015 is the control that would have
stopped it. Requires an *inventory* of expected credentials, or the "certificate added" alert is
unactionable.

**T1098.005 Device Registration** (3 groups: APT29, C0027, SolarWinds) — persistence *and*
privilege escalation. **One mitigation, M1032**, and it means *gate registration itself with
MFA*. APT29 enrolled a device to a **dormant account** after guessing its password, because
first-device self-enrolment is authenticated by the very factor it is meant to protect. Rule
worth keeping: **every account must be enrolled or disabled — there is no valid third state.**
`azure:audit` "Add device" is one of the highest-signal alerts available.

**T1685.002 Disable or Modify Cloud Log** (1 group, TA0112 Defence Impairment) — **one
mitigation, M1018**: there is no technical control, only a permissions decision. APT29 disabled
**Purview Audit on targeted accounts** *prior to* stealing mail — per-account, so the tenant
still looks audited and the compliance report still passes. Principle: **if the identity being
audited can disable the audit, there is no audit.** Same structure as the T1486 backup finding.
Missing control most places: **alerting on log-source silence**, since absence of events is
itself the detection.

**T1114.002 Remote Email Collection** (16 groups — highest in the chain, TA0009) — the
objective. APT29 used **EWS API** requests and the built-in mailbox-export feature
(`New-MailboxExportRequest`) against *"executives and IT staff"*. As with T1530, **the
application is not in the path** — Graph and EWS answer directly. Highest-consequence tenant
permission: an app registration with `Mail.Read` application permission reads every mailbox,
no user, no MFA, no Conditional Access. M1060 Out-of-Band Communications is the unusual
mitigation: do not run incident response inside the compromised tenant. Detection requirement:
**`MailItemsAccessed` enabled and retained** — which is exactly the log APT29 turned off.

#### What made this chain different

The first chain went *around* controls. This one went *underneath* them. APT29 never defeated
MFA or bypassed Conditional Access — they corrupted the systems that **issue the verdicts**:
the authentication process, the certificate authority, the device registry, the audit log. Every
control kept working correctly and kept returning "allow", because the inputs had changed.

**A control is only as trustworthy as the system that feeds it.** "Is MFA enforced?" is the
wrong question if nobody asks who can modify the authentication process, issue certificates,
register devices, or turn off the audit log. Those four questions are on no compliance checklist
and this chain turns on all four.

**Earliest break: M1026 Privileged Account Management applied to identity infrastructure as its
own admin tier** — separate credentials, separate admin workstations, just-in-time access.
Technique 3 is where the chain turns; everything after it is downstream.

**Cheapest single control:** alert on changes to federation trust, certificate credentials,
device registration, and audit configuration. Four rare event types, near-zero false positives,
each firing at a different step.

#### Two observations worth keeping

- **Privilege escalation was never a discrete step.** It was a *property* of techniques 3–5 —
  T1649 says explicitly *"to impersonate admin users"*, and T1556.007 and T1098.005 both carry
  escalation tactics. In on-prem thinking escalation is a moment you can point at; in cloud
  identity attacks it is not separable from the technique. Reviewing a design for "the privilege
  escalation control" will not find the gap.
- **Usage counts are not priorities.** The two pivotal techniques show **1 group each**; the
  endpoints show 13 and 16. Ranking work by that column would have skipped exactly the steps
  that made the intrusion possible. ATT&CK counts public reports; it does not rank risk.

#### Format change from here

Every technique from now on opens with **ATT&CK's exact definition, quoted verbatim**, followed
by an "In plain language" rewrite. The quote is what gets cited in a design document; the
rewrite is what teaches. Encoded in the tutor's teaching contract.

### 2026-08-02 — scope correction, and what actually transfers to AppSec

**The problem.** Chains 1 and 2 drifted into platform and infrastructure security. Chain 1 ended
in AD FS, AD CS, Purview and Exchange mailboxes; chain 2 ran through VPN appliances, domain
controllers, NTDS and ESXi. None of that is an application architect's remit. Scope from here:

- **In:** the application and its exposed surface; its identity (managed identity, app
  registration, service principal, workload identity); its secrets; its data stores and whether
  the app mediates access to them; its container and orchestrator; its build pipeline and
  dependencies; its OAuth and token surface; its egress.
- **Out:** domain controllers and AD internals, AD FS/AD CS, Exchange and mailbox techniques,
  VPN and network appliances, endpoint tradecraft, host forensics.

**Chain 2 abandoned at technique 9.** T1070.004 File Deletion is host forensics. Chain 2's
transferable lessons are already taught and recorded below.

#### The seven findings from chains 1–2 that do transfer

1. **T1190 → managed identity is the core application chain.** Exploit the workload, then ask
   the instance metadata endpoint (`169.254.169.254`) for a token. The attacker *inherits* a
   credential rather than stealing one, so there is nothing to rotate — RBAC scope is the only
   lever. (Chain 0.)
2. **Your application is not in the path to its own data.** Object storage answers the cloud API
   directly, so app-layer authorisation, rate limiting and audit logging are bypassed rather
   than defeated. Data protection has to live at the storage layer. (T1530.)
3. **Credential *addition* is the universal cloud persistence mechanic.** A second client secret
   or certificate on an existing app registration; a registered device; a new role assignment.
   All survive password resets. The recurring alert set — credential added, role assigned,
   device registered — came up in every chain. (T1098.x, T1649, T1098.005.)
4. **A control is only as trustworthy as the system that feeds it.** APT29 never defeated MFA or
   Conditional Access; they corrupted the systems issuing the verdicts. Applied to applications:
   ask who can modify the app registration, its credentials, its permissions and its consent
   grants. (Chain 1 wrap-up.)
5. **Preventive controls collapse as the attacker advances** — 8 mitigations at the front door,
   2 at the end. Design effort belongs at the left of the chain.
6. **Living off the land means "no malware" is not a defence.** Six consecutive Volt Typhoon
   steps used built-in tooling. For applications the equivalent is legitimate SDK and CLI calls
   against your own control plane — nothing for an endpoint agent to catch. (Chain 2.)
7. **On-prem and cloud have asymmetric policy.** Conditional Access evaluates at Entra ID token
   issuance; Kerberos/NTLM consult nothing. GPO is configuration management, not an
   authentication decision point, and it only governs machines you own. A synchronised identity
   therefore has two authentication paths of very different strength, and the attacker picks.
   Never write "protected by Conditional Access" without saying *on which path*.

#### Telemetry, reframed

The "what reveals it" sections were being skipped because they read as incident response. They
had drifted into EventCodes and correlation logic, which belong to the detection team. The four
questions that are genuinely design-time and irreversible afterwards:

1. **Can the event be produced at all?** `MailItemsAccessed` needs a licence tier; Azure blob
   data-plane logging and Windows process-creation auditing are off by default.
2. **Is retention longer than the adversary's dwell time?** Entra audit and Azure Activity Log
   default to 90 days; Volt Typhoon operated for years. You cannot buy last year's logs.
3. **Can the audited party disable the audit?** An RBAC boundary question (T1685.002).
4. **Who can read it?** The telemetry platform is a map of the organisation (T1654).

The line: the architect owns whether the evidence **exists, survives and is trustworthy**; the
detection team owns what is done with it.

#### On adversary emulation — final position

- **No to emulation frameworks** (CALDERA, full emulation plans, purple-team exercises). They
  answer *"did the detection fire?"* — the detection team's question — and generate findings an
  architect cannot fix.
- **No to Atomic Red Team on hosts.** Endpoint and AD tradecraft, out of scope, and it carries
  real authorisation and blast-radius problems. `ntdsutil` on a domain controller is
  indistinguishable from the real thing.
- **Yes to control-plane assertion testing in a sandbox subscription.** Storm-0501's procedures
  are *API calls against resources you own* — `elevateAccess/action`, `roleAssignments/write`,
  `storageAccounts/listkeys/action`, `storageAccounts/write`. In a throwaway subscription these
  are ordinary administration: no exploit, no malware, no production risk, no permission
  conversation. Each answers a question the architect owns — does the event exist, does it reach
  the workspace, and would anyone see it?

The distinction that matters: **emulation tests the SOC; assertions test your design
assumptions.** A telemetry inventory tells you a log *category* is enabled; an assertion tells
you the specific operation produces a distinguishable event that survives.

**Deliverable to build after chain 3:** `attack-learning/control-plane-assertions.md` — the
Azure control-plane operations every application project must alert on, each traceable to a real
adversary procedure with its ATT&CK ID and source report. Provenance is the point: *"Storm-0501
did this, here is Microsoft's report"* is defensible in a design review; *"best practice says
so"* is not.

#### Next: application-layer chains only

Ranked by application-layer technique coverage in the data:

| Actor | Hits | Shape |
|---|---|---|
| **TeamTNT** | 10 | Containers: malicious image, orchestrator API, escape to host, credentials in files |
| **Storm-0501** | 8 | **Cloud application → storage**, procedures named by Azure API call |
| **SolarWinds Compromise** | 6 | **CI/CD**: build compromise, code repositories, cloud identity |

Chain 3 is Storm-0501, starting 2026-08-02.

## Open questions

- **T1098.006 Additional Container Cluster Roles sits at 0 groups.** AKS RoleBindings are exactly
  this technique. The zero is a public-reporting gap, not an attacker preference — a live example
  of why absence in ATT&CK is not evidence of safety.
- **Managed identities are not modelled distinctly by ATT&CK.** They are covered implicitly under
  T1078.004, but "a credential that cannot be stolen because it is issued on demand from the
  metadata endpoint" changes the control set entirely: nothing to rotate, so RBAC scope is the
  only lever. Treat as a framework gap.
- **T1190 Exploit Public-Facing Application** — referenced repeatedly as the other entry door but
  not yet taught properly. Worth covering.
- **T1528 Steal Application Access Token — still owed.** It is in APT29's real technique set and
  was deliberately left out of chain 1 to keep the path to seven techniques. OAuth token theft
  against Microsoft 365 is directly relevant to the stack; teach it before or during chain 2.
- **T1098.002 Additional Email Delegate Permissions** — surfaced twice now (APT29's set, and as
  a route to mailbox access in T1114.002). It is the opening move of chain 2.
