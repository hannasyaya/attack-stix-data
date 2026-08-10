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
- **Every technique, mitigation and tactic ID is written with its name, every single time** —
  "T1505.003 Web Shell", not "T1505.003". Raised 2026-08-10: bare IDs are unresolvable references
  that quietly demand the recall these lessons promise never to test.

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
| 2 | TA0006 credential-access | 65 | **done** 2026-08-10 |
| 3 | TA0003 persistence | 109 | **next** |
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

Credential access (done): T1552.001 Credentials In Files, T1528 Steal Application Access Token,
T1555.006 Cloud Secrets Management Stores.

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
| T1528 Steal Application Access Token | credential-access | 2026-08-10 | **solid** |
| T1555.006 Cloud Secrets Management Stores | credential-access | 2026-08-10 | **solid** |

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
where the attacker is standing. **Corrected unaided on T1528** — secret rotation identified as
closing the T1078.004 path while leaving the issued token untouched.

**Rotating a credential does not revoke an issued token, and a workload has no session to end**
(2026-08-10, from T1528). The OAuth client-credentials flow issues **no refresh token**, so a
compromised service principal has nothing to revoke and nothing to renew — containment is a
bounded wait on access-token expiry (Entra default roughly an hour), and in that window the only
levers are on the resource side: strip role assignments, or block at the resource. "Revoke
sign-in sessions" is a **user** operation and has no target here; it is the right tool only for
a delegated user flow. Rotation is also incomplete on its own: an app registration can hold
several secrets and certificates, so enumerate every credential on it — an attacker-added one
(**T1098.001 Additional Cloud Credentials**) survives rotating yours, and is the most common
reason a "contained" identity incident is not.

**Key Vault: control-plane privilege converts into data-plane secrets** (2026-08-10, from
T1555.006). "Who can read our secrets" is answered by the access list **plus everyone who can
modify it**. Under the legacy access-policy permission model, `Microsoft.KeyVault/vaults/write`
— which resource-group **Contributor** holds — lets someone add an access policy granting
themselves data-plane read. Under the Azure RBAC permission model that path closes, since
granting a role needs `Microsoft.Authorization/roleAssignments/write`, which Contributor lacks
and **Owner** / **User Access Administrator** have. Two qualifiers that decide whether it holds
in practice: **RBAC inherits downward**, so Owner or UAA at subscription or management-group
scope flows onto the vault regardless of permission model; and **the permission model is itself
a control-plane setting**, so anyone who can write to the vault can switch it back — "we use
RBAC" is current configuration, not a durable property, without Azure Policy or a deny
assignment. Contributor also retains vault deletion and **diagnostic-settings modification**,
the control-plane route to disabling the audit log.

**The escalation is logged by default and the theft is not** (2026-08-10, from T1555.006).
`Microsoft.KeyVault/vaults/write` lands in the Azure Activity Log with no configuration;
`SecretGet` needs a diagnostic setting routing Key Vault AuditEvent to a workspace, and that is
**off by default**. ATT&CK's only analytic for this technique is AWS CloudTrail — no Azure
detection at all, for a technique whose own definition names Azure Key Vault. **One mitigation
exists (M1026)**, which is ATT&CK stating that the entire defence is who holds privilege. What
does *not* apply and gets specified anyway: private endpoints and vault firewalls (the attacker
is executing inside the network as the workload), encryption of contents (the vault decrypts for
authorised callers by design), and soft-delete/purge protection (recovery controls — they
address destruction, not disclosure).

### Tactic 2 close — credential-access (2026-08-10)

**Nothing was broken in any of the three.** The file read was permitted, the token was validly
issued, the vault request was authorised and correctly answered. That is the structural
difference from initial access: those techniques defeat a barrier, these use an **authorised
position**. Hence the thin mitigation counts — four, four, one — and hence M1047 Audit being the
closest thing to a shared control, which is the weakest kind.

**The ladder relocates the credential, it does not remove it.** Config file (T1552.001) →
metadata endpoint via managed identity (T1552.005) → Key Vault fetched by that identity
(T1555.006). Every rung is a real improvement against *leakage*; no rung changes what an
attacker holding the application's execution context can retrieve.

**The control doing the most work is not an M-number** — no mitigation spans all three. It is a
design property: **shrink what one compromised execution context can retrieve.** A vault per
application rather than per environment; a service account scoped to one namespace; a token
whose audience cannot be replayed elsewhere. Not preventing the retrieval — deciding how much a
single successful one returns.

**The tactic's output is the previous tactic's input.** Everything acquired here is spent as
T1078. Credential access and initial access are one loop, re-run against each new environment.

**Taught:** T1552.001, T1528, T1555.006. **Named and skipped, with reasons:** T1003 and T1558
(endpoint memory, NTDS, Active Directory internals); T1110 Brute Force — highest usage in the
tactic at 17 groups and skipped anyway, because its controls are identity-provider configuration
rather than an application design decision; T1040 and T1557 (network layer); T1056, T1111, T1621
(target a human at a keyboard); T1539 Steal Web Session Cookie — the closest call and the one to
add if a fourth is ever wanted; T1552.004 Private Keys, folded in as a callback.

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
