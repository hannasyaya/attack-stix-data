# Using ATT&CK in the architect's job

Read this when the user asks how to actually apply ATT&CK in their work — design reviews,
control statements, arguing for budget, talking to the detection team.

## Where ATT&CK earns its keep for an architect

You are not running a SOC. Four uses justify the learning investment:

1. **Justifying controls.** Turning "we should have MFA" into "these 42 in-scope techniques,
   used by these named groups, are addressed by MFA — here is what remains if we skip it."
2. **Finding the gap after the first control.** ATT&CK is a graph. Blocking initial access is
   one node; the value is being able to ask *and then what?* out loud in a design review.
3. **Specifying telemetry.** What the system must log is an architecture decision, made at
   design time, and expensive to retrofit. ATT&CK's detection strategies tell you what
   detection will need before anyone writes a detection.
4. **A shared vocabulary.** "T1078.004" means the same thing to your detection engineer, your
   vendor and your red team. It ends a category of circular meeting.

## Bringing it into a design review

Do not walk in with 581 techniques. Use the funnel:

1. **Scope by platform.** `attack.py scope --platforms IaaS,SaaS` — this is the universe that
   could apply.
2. **Scope by entry point.** What is actually exposed? Internet-facing app, SSO, CI/CD pipeline,
   third-party integration. Each has a small set of realistic initial-access techniques.
3. **Follow two or three chains.** Pick the plausible ones and walk them: entry → execution →
   persistence → the crown jewels. Depth beats breadth every time.
4. **Name the control at each hop**, and the residual risk.
5. **Write down the telemetry** each hop would need. This is your logging requirement.

Three well-traced chains beat a 200-row spreadsheet. The spreadsheet will not be read.

## Writing a control statement that references ATT&CK

Weak:

> The system shall implement multi-factor authentication. *(MITRE ATT&CK M1032)*

Strong:

> Administrative access to the service console and the CI/CD deployment identity shall require
> phishing-resistant MFA (WebAuthn or equivalent). SMS and push-approval are not acceptable for
> these paths.
>
> **Rationale.** Addresses T1078 Valid Accounts (56 groups observed) and T1133 External Remote
> Services (38 groups), the most common routes to privileged access in cloud-hosted
> applications. Push-based MFA is excluded because it is defeated by MFA-request generation
> (T1621), which is in active use.
>
> **Residual risk.** MFA does not address session-token theft after authentication (T1539 Steal
> Web Session Cookie); see the session-binding requirement.

The difference: a named threat, a scoped decision, an explicit exclusion with a reason, and the
gap stated rather than hidden. The residual-risk line is what makes it credible.

## Traps

**Coverage theatre.** "We mitigate 400 techniques." Coverage is not binary and rarely
measurable. If someone claims a percentage, ask: covered by which control, tested how, and what
was the false-positive rate? Usually the answer is that a spreadsheet cell was set to green.

**Mistaking the catalogue for a priority list.** ATT&CK is deliberately unranked. The usage
counts in this toolkit are a decent proxy for *prevalence*, but prevalence is not your risk —
your risk depends on your exposure, your data and who is actually interested in you.

**Skipping to sub-techniques.** There are 385 in scope. Learn the ~196 top-level techniques
first; drop to sub-techniques only when a specific control decision depends on the distinction
(for example, T1078.004 Cloud Accounts versus T1078.003 Local Accounts genuinely need different
controls).

**Treating ATT&CK as an appsec framework.** It largely starts at exploitation. Your SQL
injection flaw is not in ATT&CK; the moment it is exploited is T1190, and everything after is.
Use OWASP and threat modelling upstream, ATT&CK downstream.

**Designing detections.** Not your job, and the fastest way to burn your credibility with the
detection team. Your job is ensuring the telemetry *exists* and is retained long enough. Hand
them the log requirements; let them write the analytics.

**Ignoring the mitigation ceiling.** Only 44 active mitigations cover the whole catalogue. If a
technique has none, ATT&CK is telling you it cannot be reliably prevented — the behaviour is
indistinguishable from legitimate use. That is a detection-and-response requirement, and you
should design for containment rather than promise prevention.

## The highest-leverage controls, measured

From the current dataset, scoped to cloud, identity, containers and Linux/Windows servers — the
number of in-scope techniques each mitigation addresses:

| ID | Mitigation | Techniques |
|---|---|---|
| M1018 | User Account Management | 116 |
| M1026 | Privileged Account Management | 104 |
| M1047 | Audit | 104 |
| M1038 | Execution Prevention | 78 |
| M1042 | Disable or Remove Feature or Program | 70 |
| M1022 | Restrict File and Directory Permissions | 60 |
| M1017 | User Training | 54 |
| M1031 | Network Intrusion Prevention | 53 |
| M1040 | Behavior Prevention on Endpoint | 51 |
| M1037 | Filter Network Traffic | 44 |
| M1027 | Password Policies | 42 |
| M1032 | Multi-factor Authentication | 42 |

Read this correctly: it is breadth, not strength. Account and privilege management dominate
because identity is the substrate everything else runs on — which is the single most useful
strategic conclusion an application architect can draw from ATT&CK. It is not an argument that
user training beats MFA; a control that partially applies to 54 techniques may be worth less
than one that decisively kills 42.

Regenerate this table any time with `attack.py scope`.
