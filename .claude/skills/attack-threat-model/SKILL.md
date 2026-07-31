---
name: attack-threat-model
description: Maps a specific application or system design to the MITRE ATT&CK techniques that realistically threaten it, then produces a prioritised control backlog and the logging requirements to go with it. Use this skill whenever the user wants ATT&CK applied to an actual project rather than explained — "threat model this service", "which ATT&CK techniques apply to my architecture", "what controls does this design need", "what should we log", "review this design against ATT&CK", "build me a control backlog". Also use when the user describes a system they are designing and asks what could go wrong or what security requirements it needs.
---

# ATT&CK Threat Model

Turn a described system into three deliverables an architect can act on: the **techniques that
realistically apply**, a **prioritised control backlog** mapped to ATT&CK mitigations, and the
**telemetry requirements** the design must satisfy.

The user is a security architect and is **learning ATT&CK as they go**. Explain each concept
briefly the first time it appears. Never assume familiarity with technique IDs.

## Data access

Use the shared query script; never read the STIX JSON directly.

```bash
python3 .claude/scripts/attack.py scope --platforms IaaS,Identity Provider
python3 .claude/scripts/attack.py technique T1190
python3 .claude/scripts/attack.py mitigation M1018 --platforms IaaS
python3 .claude/scripts/attack.py logs T1190
```

See `.claude/skills/attack-tutor/SKILL.md` for the full command table. For explaining any single
technique in depth, follow the tutor's seven-part teaching contract.

**Cloud reference: Azure.** The user works in Azure — use Entra ID, subscriptions, managed
identities, Azure RBAC, Key Vault, App Service and AKS in every example and control statement,
not AWS. ATT&CK's data is AWS-weighted (`AWS:CloudTrail` appears in 142 analytics against 9 for
`azure:activity`), so when the script returns an AWS log source, give the Azure equivalent and
say you are translating. The translation table and the list of Azure log sources that genuinely
appear in ATT&CK are in `.claude/skills/attack-tutor/references/stack-map.md`.

## Step 1 — Understand the system

Ask only what you cannot infer, and ask it in one batch. You need:

- **What it is** and what it does
- **Platforms** — maps to ATT&CK scope: IaaS, SaaS, Office Suite, Identity Provider,
  Containers, Linux, Windows, macOS
- **Exposure** — internet-facing, internal, partner-facing?
- **Identity model** — who authenticates, how; what machine identities exist (managed
  identities, app registrations with client secrets, CI/CD service connections)
- **Data** — what an attacker would actually want
- **Integrations** — third parties, suppliers, federated tenants

If the user has pointed you at a repository or design document, read it first and only ask about
the gaps. Do not interrogate them for things you can read.

## Step 2 — Scope

Run `scope --platforms ...` for the real technique count and the highest-leverage mitigations.
State the number honestly, then narrow: the full scope will be hundreds of techniques and that
is not a deliverable.

Narrow by **entry point**, which is what actually differentiates one system from another:

- Internet-facing app → T1190 Exploit Public-Facing Application
- Any human login → T1078 Valid Accounts, T1566 Phishing
- SSO/federation → T1078.004 Cloud Accounts, T1199 Trusted Relationship
- CI/CD pipeline → T1195 Supply Chain Compromise, T1078 on the pipeline identity
- Third-party integration → T1199 Trusted Relationship
- Exposed management interface → T1133 External Remote Services

## Step 3 — Trace two or three chains

**This is the core of the exercise.** A list of techniques is not a threat model; a chain is.

For each realistic entry point, walk: **entry → execution → persistence → privilege escalation →
the data they came for**. At each hop name the technique, the control that breaks the chain, and
what the system would have to log for anyone to notice.

Three well-traced chains beat a hundred-row matrix. The matrix does not get read; the chain
changes the design.

## Step 4 — Control backlog

Group by ATT&CK mitigation, ordered by coverage in the user's actual scope (from `scope` and
`mitigation --platforms`). For each control give:

- The ATT&CK mitigation ID and name
- **The concrete decision for this system** — not the generic label. "M1026 Privileged Account
  Management" is a category; "the app's managed identity gets Storage Blob Data Reader scoped to
  one container, not Contributor on the storage account" is a backlog item.
- Which techniques it addresses, and the observed usage count
- **Residual risk** — what it does not cover. This is what makes the backlog credible.

Anchor on what actually buys coverage. In this user's default scope: M1018 User Account
Management (116 techniques), M1026 Privileged Account Management (104), M1047 Audit (104),
M1038 Execution Prevention (78), M1032 MFA (42). Identity controls dominate because identity is
the substrate. Verify with `scope --platforms` for the project's real platform set rather than
quoting these numbers blindly.

Flag any in-scope technique with **no mitigations** — ATT&CK is saying it cannot be reliably
prevented, so it needs detection and containment instead. Silently dropping these is the most
common way a control backlog lies.

## Step 5 — Telemetry requirements

Run `logs <ID>` on the techniques in the traced chains. Translate the analytics into
**requirements on the system**, phrased as things the design must do:

> The application shall emit structured access logs including source IP, authenticated
> principal, request path and response status, retained 90 days and written to storage the
> application's own identity cannot modify.

Not "monitor for suspicious requests". The user owns whether the telemetry exists and is
tamper-resistant; the detection team owns what is done with it. Keep that line clean — it is
also what keeps their credibility with that team.

Cover: application/access logs, authentication events, control-plane audit logs, process
execution on hosts or containers, and egress network flow. Note retention and integrity, since
both are design decisions that are expensive to retrofit.

## Step 6 — Deliverable

Write a markdown document to the project (or `attack-learning/` in this repo) with:

1. **System summary** and the scope assumptions you worked from
2. **Attack chains** — the two or three traced paths
3. **Control backlog** — prioritised, each with the concrete decision and residual risk
4. **Telemetry requirements**
5. **What this does not cover** — explicitly

Offer to publish it as an artifact if they want something shareable.

## Honesty rules

- **Never invent IDs.** Every technique, mitigation and group name must have come from the
  script.
- **Say what you assumed.** Threat models built on wrong assumptions are worse than none.
- **State the gaps.** ATT&CK is not exhaustive, is biased toward publicly reported intrusions,
  and covers little about application logic flaws — business logic abuse, authorisation bypass
  and injection largely live upstream in threat modelling and OWASP.
- **Do not produce coverage percentages.** "We cover 73% of ATT&CK" is meaningless and actively
  misleads whoever reads it next.
