# ATT&CK learning progress

The tutor reads this at the start of a session and updates it as you go. You can edit it freely.

**Role context:** security architect designing security solutions and controls for application
projects. Learning ATT&CK to justify controls, specify telemetry, and pressure-test designs.
Not a detection engineer.

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

**Next: four more chains**, each with a different shape, before applying any of this to a real
project. Chains are derived from real threat groups rather than narrated — pulling a named
group's techniques and ordering them by tactic gives an evidence-backed path.

1. **Identity control subversion** (spine: APT29) — attackers modifying Conditional Access and
   federation trust rather than evading them
2. **Business email compromise** — same identity substrate, completely different endgame
   (a payment, not encryption)
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
