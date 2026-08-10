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
| 1 | TA0001 initial-access | 22 | **done** 2026-08-10 |
| 2 | TA0006 credential-access | 65 | **next** |
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

Initial access (done): T1190, T1078.004 Cloud Accounts, T1195.002 Compromise Software Supply
Chain.

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
| T1195.002 Compromise Software Supply Chain | initial-access | 2026-08-10 | **solid** |
| T1552.001 Credentials In Files | credential-access | 2026-08-10 | **shaky** |

**T1078.004** — the boundary against T1528 and T1550 landed; **mitigation applicability did
not.** The check asked what MFA and Conditional Access buy you when a partner's CI/CD service
principal is breached, and the answer was that the attacker still needs the user's MFA device.
Not an open gap, though: the same applicability reasoning was reached **unaided** one technique
later on T1195.002. Retest it in tactic 2 rather than reteaching it.

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

**Code signing attests origin and post-signing integrity — never pre-signing integrity**
(2026-08-10, from T1195.002). A valid signature says who produced the artifact and that nobody
altered it *after* it was signed. Whether the publisher's build environment was already
compromised is outside what the mechanism can assert, and that is precisely where APT41 worked
("injected malicious code into legitimate, signed files" from inside production) and where the
3CX attacker worked. Practical consequence: signature verification **splits this technique's
procedures in two.** Blind against publisher-build compromise (SolarWinds Orion, 3CX, M.E.Doc,
APT41); effective against repackaged or lookalike artifacts (Moonstone Sleet's trojanised PuTTY,
GOLD SOUTHFIELD's backdoored installers from a compromised download site). Specify the control,
knowing which half it covers. Phrasing for the room: *"signing gives us provenance and
tamper-evidence after the fact — no assurance about the vendor's build environment."*

**A managed identity is a permission the execution context carries, not a secret the application
knows** (2026-08-10, from T1552.001). Moving a connection string from a config file into Key
Vault removes the *standing artefact* — nothing left in an image layer, repo, backup or pipeline
log — and that is a real win against leakage. It does not restrict the secret from the
application's own context: any code executing as the workload can request a token from the
metadata endpoint and spend it at the vault, because the request is indistinguishable from the
application's own. The technique moves (T1552.001 → T1552.005 + T1555.006); the reachability
does not. **Against leakage, transformative. Against compromise of the application, unchanged.**
What the move genuinely adds is visibility — Key Vault records the secret retrieval as a
data-plane operation, and that logging is **off by default**.

**The recurring failure mode: assuming a control's boundary sits tighter than it does**
(2026-08-10). Twice in three techniques — MFA imagined to cover a machine identity (T1078.004),
a managed identity imagined to restrict access from the app's own context (T1552.001). The
correcting question for any specified control: *what is on the inside of its boundary?* That is
where the attacker is standing.

### Tactic 1 close — initial-access (2026-08-10)

**The entry technique varies; the blast radius does not.** T1190 exploits the code, T1078.004
authenticates as the workload, T1195.002 arrives inside software installed on purpose — three
unrelated doors, and in all three the size of the incident is set by the same thing: what the
compromised identity was permitted to reach. Entry techniques are numerous, cheap and partly
outside the architect's control. The privilege scope behind the door is one decision, made once,
in a template the architect owns. **You cannot spend your way to a reliable front door.**

**Mitigation count collapses as the compromise moves away from your own code.** T1190 offers a
rich preventive set; T1078.004 offers seven, of which three (M1032, M1017, M1027) are noise for
a machine identity; T1195.002 offers two — and one of them, M1051 Update Software, is the
*delivery vehicle* in the SolarWinds and M.E.Doc procedures. The further left the compromise
happens, the fewer controls you own, which is an argument for spending architecture effort where
control still exists.

**Taught:** T1190, T1078.004, T1195.002. **Named and skipped, with reasons:** T1133 and T1669
(network appliances), T1189 and T1566 (target staff, not the application), T1091 and T1200
(physical access), T1659, T1199 (folded into T1078.004 — the partner-pipeline scenario is the
same problem with a credential attached).

---

## Open questions

*Empty at reinitialisation.*
