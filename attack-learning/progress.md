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

**4 techniques covered** — a complete identity attack chain, taught 2026-07-31.
Working through the identity block. Next candidates: T1098.001 Additional Cloud Credentials,
M1026 Privileged Account Management as a control deep-dive, or T1114.002 Remote Email Collection
to follow the chain onward.

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
