# ATT&CK learning progress

Reinitialised **2026-08-03**. Nothing below is assumed learned.

The previous log — four chains, ~25 techniques, taught in a long-form format that did not work —
is in git history at commit `f46e08a` if any of it is ever wanted back. It was reset at the
user's request along with the curriculum.

The tutor reads this file at the start of a session and updates it as you go. You can edit it
freely.

---

## Who this is for

**Security architect working in application security** — designing security solutions and
controls into application projects. Learning ATT&CK to justify controls, specify telemetry, and
pressure-test designs.

**Not** a detection engineer or SOC analyst, and **not responsible for platform or
infrastructure security.**

| | |
|---|---|
| **In scope** | The application and its exposed surface; its identity (managed identity, app registration, service principal, workload identity); its secrets and how it gets them; its data stores and whether the app mediates access to them; its container and orchestrator; its build pipeline and dependencies; its OAuth and token surface; its egress |
| **Out of scope** | Domain controllers and Active Directory internals, AD FS and AD CS, Exchange and mailboxes, VPN and network appliances, endpoint and workstation tradecraft, host forensics |

**Stack:** Cloud (IaaS/SaaS), Identity Provider, Containers, Linux/Windows servers.
581 of 697 Enterprise techniques are in scope for those platforms.

**Cloud reference: Azure.** Entra ID, subscriptions and management groups, managed identities,
Azure RBAC, Key Vault, App Service, AKS, Storage accounts, Microsoft 365 — never AWS or GCP.
ATT&CK's own data is AWS-weighted, so the tutor translates AWS log sources to their Azure
equivalents **and says when it is translating**.

---

## How lessons work

**One technique per message, start to finish, ~900 words in seven headed sections:**

1. **What it is** — MITRE's exact wording, plain language, then **the boundary**: what separates
   it from the adjacent techniques it gets confused with. Naming the wrong technique in a design
   review means specifying the wrong control.
2. **Why the adversary does it** — the goal it serves.
3. **On your stack** — one concrete Azure scenario.
4. **What real groups did** — four or five named groups and what each actually did, quoted not
   summarised, then the pattern across them.
5. **What stops it** — mitigations as design requirements, including **at least one that does
   not apply and why**. Knowing which controls are inapplicable stops you specifying security
   theatre.
6. **What reveals it** — one or two of the four telemetry-as-architecture questions.
7. **Check** — a design-review scenario. Answering it is how a technique moves from `untested`
   to `solid`.

**Why this shape.** Three shorter formats were tried on 2026-08-03 and all were rejected: a
250-word card (dropped the procedure evidence), four chunks in one message (~100 words each),
and four chunks as four messages (fragmented the technique). The original complaint — *"I am
lost between the beginning and the end"* — was a **navigation** problem, not a length problem.
The fix is a bold heading on every section, no tables, and no closing flourish.

- **Chunk 2 is never skipped.** A named group and the concrete thing it did is what makes a
  technique arguable in a design review. Reducing it to "13 groups use this" was a failure.
- **Procedures come from the sub-technique**, not the parent, whenever one exists — parent-level
  evidence skews to whatever was most reported and is often out of scope.
- **Answering the question is how a technique moves from `untested` to `solid`.** Never a
  definition question, never a request for an ID from memory.
- **Verbatim quotes are always checked against the query script**, never written from memory.

Rules live in `.claude/skills/attack-tutor/SKILL.md`. Assessment questions are built by the
`attack-examiner` agent.

---

## The route: a tactic tour

Walking the 13 tactics one at a time — what the adversary is trying to achieve at that stage,
then the application-layer techniques that matter within it.

Chosen over the alternatives for a reason worth recording: **the usage-ranked curriculum is a
bad fit for this user.** The top techniques by real-world adversary usage are PowerShell,
malicious file attachments, Windows Command Shell and spearphishing — endpoint and workstation
material. Of the top twelve, only T1190 is squarely application security. Ranking by popularity
would spend most of the time on another team's job.

Order below is not ID order. It follows the attack lifecycle but opens with the smallest tactic
and the one closest to the user's own surface.

| # | Tactic | In scope | Status |
|---|---|---|---|
| 1 | TA0001 initial-access | 22 | **next** |
| 2 | TA0006 credential-access | 65 | not started |
| 3 | TA0003 persistence | 109 | not started |
| 4 | TA0004 privilege-escalation | 96 | not started |
| 5 | TA0007 discovery | 49 | not started |
| 6 | TA0009 collection | 37 | not started |
| 7 | TA0010 exfiltration | 19 | not started |
| 8 | TA0040 impact | 33 | not started |
| 9 | TA0112 defense-impairment | 46 | not started |
| 10 | TA0008 lateral-movement | 23 | not started |
| 11 | TA0002 execution | 61 | not started |
| 12 | TA0011 command-and-control | 45 | not started |
| 13 | TA0005 stealth | 146 | not started |

**Three techniques per tactic**, chosen by where you have architectural decisions rather than by
usage count — depth over breadth. Every other technique in the tactic is **named in the opener
with the reason it is skipped**, so a subset is never mistaken for the whole.

Initial access: T1190 (done), **T1078.004 Cloud Accounts**, **T1195.002 Compromise Software
Supply Chain**.

**Not in the table:** reconnaissance (TA0043) and resource-development (TA0042). Both are
`PRE`-platform, carry M1056 Pre-compromise — ATT&CK's marker for "no preventive control exists" —
and offer the architect no decisions. They get one short message at the start of tactic 1, not a
tour.

The goal for each tactic: be able to explain it to a colleague, and place an unfamiliar
technique into the right one during a design review without help.

---

## Retention table

`untested` — taught but never checked · `shaky` — checked, answer showed a gap · `solid` —
checked and answered well.

| Technique | Tactic | Taught | Status |
|---|---|---|---|
| T1190 Exploit Public-Facing Application | initial-access | 2026-08-03 | **solid** |
| T1078.004 Cloud Accounts | initial-access | 2026-08-10 | **shaky** |

**T1078.004** — the boundary against T1528 and T1550 landed; **mitigation applicability did
not.** The check asked what MFA and Conditional Access buy you when a partner's CI/CD service
principal is breached, and the answer was that the attacker still needs the user's MFA device.
Retest this, and retest the does-not-apply reasoning generally.

---

## Findings

Observations worth keeping, recorded as they come up.

**MFA and Conditional Access do not evaluate workload identity sign-ins** (2026-08-10, from
T1078.004). A service principal authenticating by client secret or certificate uses the OAuth
client-credentials flow: no user, no prompt, no device, so an MFA policy evaluates to
not-applicable rather than to deny. Entra has Conditional Access for workload identities, but it
is a separate premium licence and supports only location and risk conditions — there is no
second factor a machine can present. *"We require MFA"* is therefore a statement about a subset
of the authentication surface, and the subset excludes every machine identity in the tenant.
**Naming the inapplicable control is the design-review move** — it is usually news in the room.

---

## Open questions

*Empty at reinitialisation.*
