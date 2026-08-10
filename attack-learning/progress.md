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
pressure-test designs. **Not** a detection engineer or SOC analyst.

### Scope changed 2026-08-10: on-premises foundation first

The user asked to **restart on standard on-premises environments**: *"I don't want to go in
modern environments like containers or cloud for beginners learning. I will do it after the
foundation is done."* They were told that general on-prem means teaching infrastructure security
— domain controllers, Active Directory internals, endpoint tradecraft — which the earlier remit
excluded. **They chose the broad scope with that known.** Settled; do not reopen.

| | |
|---|---|
| **In scope** | Windows and Linux servers and workstations; Active Directory — domain controllers, Kerberos, delegation, group policy, certificate services; on-prem application servers (IIS, Tomcat, Apache) and their databases; file shares; local and domain accounts and credential stores; endpoint execution, host persistence, host forensics; the internal network |
| **Deferred, not excluded** | Cloud (Azure/AWS/GCP), Entra ID, containers and orchestrators, SaaS, CI/CD pipelines — returned to once the foundation is done |

**Stack:** Linux and Windows, on-premises. **507 of 697 Enterprise techniques** are in scope
(176 top-level). Query with `--platforms Linux,Windows` — the script's default is still the old
cloud-inclusive scope.

**Illustrate with plain on-prem infrastructure**: a Windows domain, a member server running IIS
or Tomcat, SQL Server, an SMB file share, a Linux application host, a service account in Active
Directory. No Azure, AWS, Kubernetes or SaaS examples while the foundation is running — only
brief callbacks to the cloud techniques already taught.

**Telemetry honesty for on-prem:** ATT&CK's analytics lean on `WinEventLog:Security`,
`WinEventLog:Sysmon`, `auditd:SYSCALL` and `NSM:Flow`. **Sysmon is not installed by default**,
auditd rules must be written, Windows command-line process auditing is off by default, and
PowerShell script block logging must be enabled by policy. Where ATT&CK names one of these, say
the evidence does not exist unless someone deployed it.

**The job did not change, only the scope.** Still end every technique at a design decision, and
where an infrastructure technique has an application consequence — the service account the app
runs as, an app server's file permissions, a database the app owns — lead with that.

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

**Restarted at initial-access on 2026-08-10** with the on-prem scope. Counts below are
`--platforms Linux,Windows`.

**The argument against a usage-ranked curriculum no longer holds, and that is worth recording.**
It was rejected in the cloud scope because the top techniques by adversary usage — PowerShell,
malicious file attachments, Windows Command Shell, spearphishing — were endpoint and workstation
material, i.e. another team's job. Under the on-prem scope **all of them are in scope**, so the
tactic tour now naturally arrives at the most-used techniques in the framework rather than
avoiding them. The tour is kept because walking by adversary goal still teaches structure that a
ranked list does not.

Order follows the attack lifecycle. It differs from the cloud order: **execution and lateral
movement move up sharply**, because on-prem they carry the classic intrusion story that cloud
identity attacks skip entirely.

| # | Tactic | In scope | Status |
|---|---|---|---|
| 1 | TA0001 initial-access | 21 | **next** |
| 2 | TA0002 execution | 48 | not started |
| 3 | TA0003 persistence | 91 | not started |
| 4 | TA0004 privilege-escalation | 79 | not started |
| 5 | TA0006 credential-access | 58 | not started |
| 6 | TA0007 discovery | 42 | not started |
| 7 | TA0008 lateral-movement | 19 | not started |
| 8 | TA0009 collection | 32 | not started |
| 9 | TA0011 command-and-control | 45 | not started |
| 10 | TA0010 exfiltration | 17 | not started |
| 11 | TA0040 impact | 30 | not started |
| 12 | TA0112 defense-impairment | 34 | not started |
| 13 | TA0005 stealth | 141 | not started |

**Three techniques per tactic**, chosen by where you have architectural decisions rather than by
usage count — depth over breadth. Every other technique in the tactic is **named in the opener
with the reason it is skipped**, so a subset is never mistaken for the whole.

**Cloud track, completed 2026-08-10 before the scope change** — kept for the return trip, not
repeated: initial-access (T1190 Exploit Public-Facing Application, T1078.004 Cloud Accounts,
T1195.002 Compromise Software Supply Chain); credential-access (T1552.001 Credentials In Files,
T1528 Steal Application Access Token, T1555.006 Cloud Secrets Management Stores); persistence,
partial (T1505.003 Web Shell, T1098.001 Additional Cloud Credentials, T1098.006 Additional
Container Cluster Roles — taught, never checked).

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
| T1505.003 Web Shell | persistence | 2026-08-10 | **solid** |
| T1098.001 Additional Cloud Credentials | persistence | 2026-08-10 | **shaky** |
| T1098.006 Additional Container Cluster Roles | persistence | 2026-08-10 | untested |

Everything above is the **cloud track**, taught before the 2026-08-10 scope change. It stays on
the record and is not re-taught; the on-prem rows start below as the tour restarts at
initial-access.

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

**Azure has two permission systems and privilege converts between them** (2026-08-10, from
T1098.001 Additional Cloud Credentials). **Azure RBAC** governs resources — subscriptions,
resource groups, storage, Key Vault — with Owner/Contributor/Reader scoped to a resource
hierarchy. **Microsoft Graph permissions and Entra ID roles** govern the directory — users,
groups, app registrations, service principals — with roles like Global Administrator and
Application Administrator and permissions like `Application.ReadWrite.All`. Separate systems,
separate administrators, almost never reviewed together. An identity holding
`Application.ReadWrite.All` and **no** Azure RBAC role at all can still write a credential to a
service principal that holds Owner on production, then authenticate as it — which is why that
permission is treated as Global Administrator-equivalent. The design-review question that
catches this and the Key Vault case alike: **can this identity become an identity that has what
it lacks?**

**Creating an identity is the weak path; credentialing an existing one is the strong path**
(2026-08-10). A new app registration (**T1136.003 Cloud Account**) starts with zero permissions,
needs a second privileged step to be useful, and puts a conspicuous new principal in the
directory. Adding a credential to an existing privileged identity (**T1098.001 Additional Cloud
Credentials**) creates no new object, needs no consent or role assignment, and inherits privilege
granted legitimately years earlier. This was the miss on the T1098.001 check.

**MFA registration is a persistence mechanism, not only a control** (2026-08-10). Storm-0501
"reset the password of identified administrator accounts that lack MFA and registered their own
MFA method" — so **M1032 Multi-factor Authentication** is listed as a mitigation for a technique
whose procedure consists of enrolling MFA. Specifying MFA without controlling MFA *registration*
is close to circular. Similarly **M1030 Network Segmentation** is noise for the Entra case:
adding a credential is an API call to a global Microsoft Graph endpoint with no network path to
segment; it is on the list for the IaaS SSH-key scenario in MITRE's description.

**Entra audit log retention is the binding telemetry question here** (2026-08-10). Credential
additions to applications and service principals are recorded natively with no configuration —
one of the highest-signal events in the tenant, since a certificate added outside a change
window has almost no benign explanation. But default retention is roughly a month, less on the
free tier, against SolarWinds-scale dwell times of many months. Routing Entra audit logs to a
Log Analytics workspace with real retention is the requirement, and it is not on by default.

**A deployment is not a remediation** (2026-08-10, from T1505.003 Web Shell). Pipelines converge
the target toward a declared desired state; they do not remove what nobody declared. Azure App
Service zip deploy **overlays** the package onto `/home/site/wwwroot` and leaves unlisted files
alone by default, and `/home` is persistent storage that survives restarts, scaling and instance
replacement. So a web shell written to the runtime filesystem is never redeployed — it is simply
never deleted. Distinguish this from a shell that reached the build artifact, which is
**T1195.002 Compromise Software Supply Chain** and needs different controls. The strongest fix is
`WEBSITE_RUN_FROM_PACKAGE=1`: the app runs from a mounted package, `wwwroot` becomes read-only,
there is no writable served directory, and every deploy is a real replacement. Container
equivalent: a read-only root filesystem.

**Choosing a managed service transfers the layers, not the risk** (2026-08-10, from T1505.003
Web Shell, raised by the user asking why App Service security is theirs at all). PaaS genuinely
removes kernel patching, host hardening, container escape and OS-level file permissions from the
architect's remit — a real reduction, worth claiming. What remains is almost entirely design-time
configuration nobody else in the delivery chain is positioned to decide: whether the served
directory is writable, where uploads land, which runtime handlers exist, whether HTTP logs are
routed anywhere. A web shell in `wwwroot` is *deployment content* — Microsoft will never flag or
remove it, because it is indistinguishable from the application.

**A web application firewall acts at the entry, not at the shell** (2026-08-10). It may well
catch the request that *plants* a shell — that is **T1190 Exploit Public-Facing Application** —
and has real value there. It is structurally blind to *use* of the shell, because a WAF is a
pattern matcher over request content, not an authorization layer over the URL space: it holds no
inventory of which URLs legitimately exist, the command usually travels in a POST body, cookie
or custom header, and the response is plain text rather than attack grammar. Commodity shells
have signatures; obfuscated and custom ones do not.

**A web shell is the opposite of a reverse shell** (2026-08-10). Reverse shell = the host dials
outbound, so egress filtering is the control. Web shell = the attacker connects **inbound** over
the HTTPS listener you already publish, so no outbound connection exists and egress control sees
nothing. They combine: shells are used to launch follow-on **T1090 Proxy** / **T1572 Protocol
Tunneling** / **T1071.001 Web Protocols** channels — reGeorg, in four of this technique's
procedures, is an HTTP tunnel.

**Upload handling, on-prem form of the cloud rule** (2026-08-10). The principle is not "use Blob
Storage" — it is that **the location written to must not be a location that executes**. On-prem:
store uploads outside the document root and stream them through application code; if they must
sit under the root, remove the interpreter handler for that path (**M1042 Disable or Remove
Feature or Program**); mount the volume `noexec`; run the writing and serving processes as
different accounts (**M1018 User Account Management**); generate the stored filename yourself and
validate content by its bytes, never by a client-supplied extension.

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
