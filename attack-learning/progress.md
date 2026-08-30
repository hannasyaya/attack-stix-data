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
3. **On your stack** — one concrete on-premises scenario, named services.
4. **What real groups did** — four or five named groups and what each actually did, quoted not
   summarised, then the pattern across them. **In report mode this section becomes "what the
   attacker did in the report"**, walked through in mechanical detail, with other groups reduced
   to a short corroboration afterwards.
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
- **Answers are marked plainly, with no softening.** Instructed 2026-08-10: *"I don't like this
  kindness when you say that is the answer most people have. I don't need this compassion when I
  failed."* No "that's a common mistake", no normalising a wrong answer, no reassurance about
  progress or readiness, no softener before a correction. Stating what an answer got right stays
  — that is information. Stating that other people get it wrong too is not.

Rules live in `.claude/skills/attack-tutor/SKILL.md`. Assessment questions are built by the
`attack-examiner` agent.

---

## Report 1 (closed 2026-08-24): learning by report - Cobalt Kitty

The user's instruction: *"I want to learn by report and here is the first report."* The tactic
tour is **paused, not abandoned** — it stopped after the TA0003 Persistence opener, before
T1053.005 Scheduled Task was taught.

**Report 1: Cybereason, *Operation Cobalt Kitty* (2017), by Assaf Dahan.** OceanLotus / APT32
(G0050) against a global corporation in Asia. 100 pages in two parts — the attack lifecycle
(pages 1–32) and the attackers' arsenal (pages 33–100, malware analysis, largely out of scope
for an architect). Text extracted to the scratchpad and read in full before any teaching.

**Why the switch costs almost nothing.** The report covers six of the seven techniques already
taught on the on-prem track — T1566.001 Spearphishing Attachment, T1204.002 Malicious File,
T1059.001 PowerShell, T1047 Windows Management Instrumentation, plus valid-account reuse — and
its foothold section is exactly the three persistence techniques the tour was about to teach:
T1053.005 Scheduled Task, T1547.001 Registry Run Keys / Startup Folder, T1543.003 Windows
Service. The tour's next three arrive with real evidence attached instead of a curriculum note.

**The source relationship worth showing the user.** MITRE's own APT32 procedure text for
T1547.001, T1053.005, T1543.003, T1574.001, T1003.001, T1021.002, T1550.002, T1550.003, T1046,
T1218.005 and T1027.010 traces back to *this report*. Reading the report and then the ATT&CK
entry shows what the model keeps and what it throws away — a 30-page intrusion compressed to
*"APT32 has used scheduled tasks to persist on victim systems."*

**The report's shape, which is a lesson in itself.** `chain APT32` over `--platforms
Linux,Windows` returns 78 techniques: 20 stealth, 13 execution, 10 discovery, 7 persistence —
and **zero impact**. Espionage, not extortion. Nothing is encrypted, nothing is destroyed; the
objective is mail and documents from named executives.

### Curriculum — 15 techniques, in the report's own order

**Corrected 2026-08-11, on the user's catch:** *"The penetration starts by spearphishing but you
didn't select it."* Right, and it was a real defect. The report's phase 1 has **two** penetration
paths — a link to a fake Flash installer, and a Word attachment — and only the attachment path
was covered by an existing lesson (T1566.001 Spearphishing Attachment, taught 2026-08-10).
T1566.002 Spearphishing Link had never been taught and was wrongly put on the skipped list, so
the report's own opening move was missing from a curriculum built on the report's sequence.
**T1053.005 Scheduled Task was therefore taught out of order** and is renumbered 2/13.

**Rule this produced:** in report mode, every technique in the report's *first* phase gets taught
or explicitly called back **before** anything downstream of it. A report's value is its sequence;
starting in the middle discards the thing the report was chosen for.

| # | Technique | Report section | Why it earns a slot |
|---|---|---|---|
| 1 | T1566.002 Spearphishing Link | 1 | Path A. The mail control never sees the payload — it arrives later, over HTTP, from a redirector |
| 2 | T1566.001 Spearphishing Attachment | 1 | Path B. **Callback** — taught 2026-08-10, `solid`. Delivered as the report's second penetration path |
| 3 | T1059.005 Visual Basic | 1 / 2.1 / 2.4 | The macro itself, and macro policy — the control that stops path B dead. Recurs in the Run keys and the Outlook backdoor |
| 4 | T1053.005 Scheduled Task | 1, post-infection | Where the macro lands; two tasks named "Windows Error Reporting" |
| 5 | T1218.005 Mshta | 1 / 3.1 | Signed Windows binary fetches and runs attacker code. Names T1218.010 Regsvr32, T1218.011 Rundll32 |
| 6 | T1547.001 Registry Run Keys / Startup Folder | 2.1 | Five Run keys, VBScript hidden in NTFS alternate data streams |
| 7 | T1543.003 Windows Service | 2.2 | Services created and modified to load PowerShell |
| 8 | T1574.001 DLL | 2.2 / 2.3 | Phantom DLL hijacking of Wsearch; side-loading against GoogleUpdate. Trust in a *path*, not an identity |
| 9 | T1137 Office Application Startup | 2.4 / 3.4 | VbaProject.OTM replaced — an application's own extension model as persistence *and* as C2 |
| 10 | T1071.004 DNS | 3.3 | Tunnelling via 8.8.8.8 and 208.67.222.222, chosen because nobody blocks them |
| 11 | T1071.001 Web Protocols | 3.1 / 3.2 / 3.5 | Malleable C2 profiles; NetCat configured for the victim's own proxy |
| 12 | T1046 Network Service Discovery | 4.1 | Whole-range scanning. Carries the segmentation argument the user has missed three times |
| 13 | T1003.001 LSASS Memory | 5.1.1 | 14 recompiled Mimikatz variants — antivirus is not a control against a rebuilt tool |
| 14 | T1550.002 Pass the Hash | 5.2 | Names T1550.003 Pass the Ticket. Why the password resets did not help |
| 15 | T1021.002 SMB/Windows Admin Shares | 5.3 | C$ and ADMIN$ via net.exe; 35+ machines including the AD server |

**Corrected again 2026-08-11, same defect, caught by the user a second time:** *"The second
technique is supposed to be the spearphishing word file with malicious macro I think."* Right.
Phase 1 has two paths and only path A was delivered. **A callback that is promised in an opener
and never delivered is a technique that was skipped** — "callbacks only for T1566.001" was
written and then nothing followed it. Curriculum goes to 15: the T1566.001 Spearphishing
Attachment callback becomes its own numbered slot, and T1059.005 Visual Basic is promoted off
the skipped list because macro policy is the control that stops path B and nothing else in the
curriculum carries that decision.

**Renumbering is now closed.** Three renumbers in one session cost the user their place — they
had to ask *"Where is the 2nd technique"*. Numbers are fixed at 15; anything else found in the
report gets appended, never inserted.

**Named and skipped**, so the subset is not mistaken for the whole:
T1059.005 Visual Basic, T1027.010 Command Obfuscation, T1027.013 Encrypted/Encoded File,
T1112 Modify Registry, T1564.004 NTFS File Attributes, T1036.005 Match Legitimate Resource Name
or Location, T1102 Web Service, T1105 Ingress Tool Transfer, T1571 Non-Standard Port, T1570
Lateral Tool Transfer, T1087.001 Local Account, T1018 Remote System Discovery, T1016 System
Network Configuration Discovery, T1049 System Network Connections Discovery, T1033 System
Owner/User Discovery, T1135 Network Share Discovery, T1114.001 Local Email Collection, T1041
Exfiltration Over C2 Channel.

**Deferred from the tour's persistence list**, displaced by the report's own evidence: T1136.001
Local Account and T1556 Modify Authentication Process.

**The date problem, to be stated in every message where it bites.** This is 2017 and Windows
7-era — Outlook 2010 (`Office\14`), no Credential Guard, no AMSI-backed script block logging by
default, no Attack Surface Reduction rules, PowerShell v2 downgrade still available. Controls
that would change the outcome today must be named as *today's*, not read back into the report.

**The control-defeat sentences** — collect these across the report; they are the reason to read
one. Already found: IT ordered frequent password resets during the incident and the attackers
had deployed a tool that hooks the password-change function to keep up; PowerShell execution
restrictions were in place and were bypassed with PSUnlock loading the runtime through
rundll32; 80+ payloads recovered, **two** known to VirusTotal at the time.

---

## The route changed 2026-08-24: Report 2, Lynx ransomware

**Cobalt Kitty is closed.** The user said *"Let's start over with this report"* on 2026-08-24.
It stopped at 5/15 — slots 6-15 never taught, the T1218.005 Mshta check never answered. Not
resumed. The five techniques it did deliver stay on the retention table.

**Report 2: The DFIR Report, *Cat's Got Your Files: Lynx Ransomware* (published 2025-12-17).**
Intrusion early March 2025. Analysts Friff and Daniel Casenove, reviewed by MittenSec. The user
pasted the full report text; the site is blocked by this environment's egress proxy, so work
from their paste, not from a fetch.

**Check format, settled 2026-08-24 and then changed the same day.** The hybrid (four MCQ plus
one open) ran for slots 2, 3 and 4 and was withdrawn once the MCQ instrument was found broken -
see the finding below. The user's instruction: *"On repasse a une question ouverte, forme
initiale. On fait les qcm a la fin du rapport."* So:

- **Section 7 of every technique: one open question**, the original format. It tests production,
  which is the architect's actual output, and it is the only instrument that has produced
  reliable signal in this session.
- **End of report: one cumulative MCQ set**, built under the corrected distractor rule. Hand it
  to the `attack-examiner` agent - it exists for exactly this in the repo and does not carry the
  habit of teaching inside the correct option. Offer it when the report closes.

The 2026-08-11 question about MCQ format is closed by this.

### Two structural facts that shape every lesson

**ATT&CK has no Lynx object.** `chain "Lynx"` returns nothing — no group, no campaign, no
software. The opposite of Cobalt Kitty, where eleven ATT&CK procedures trace back to the report
itself. Consequence: section 4 is the report's own evidence, and groups from `actors` are
unrelated adversaries used only to show whether the report's version is typical. Never blur them.

**The date problem inverts.** Cobalt Kitty was 2017 and needed constant "this control exists
now" notes. March 2025 is current — every control discussed was available to this victim and
mostly was not deployed. What has moved is ATT&CK: the report's **"Defense Evasion"** heading is
a tactic that no longer exists, split into TA0005 Stealth and TA0112 Defense Impairment. Say so
when it comes up.

**The shape.** Nine days, ~178 hours to ransomware. No malware until the final payload, no C2
framework, no credential dumping, no exploit. The whole intrusion is valid credentials plus RDP
plus a network scanner. The absence is the lesson: no execution-prevention story, no antivirus
story, nothing for a mail gateway to do. The attacker's only concession to stealth is naming an
account `administratr`.

### Curriculum - 16 slots, in the report's own order

| # | Technique | Report section | Why it earns a slot |
|---|---|---|---|
| 1 | T1650 Acquire Access + T1588.002 Obtain Capabilities: Tool + T1583.003 Virtual Private Server | Case Summary, C2 | Pre-compromise, one short message |
| 2 | T1133 External Remote Services | Initial Access | **Callback + retest** - `shaky` from 2026-08-10 |
| 3 | T1078.002 Domain Accounts | Initial Access | **Callback** - `solid`. Two accounts, neither stolen on-site |
| 4 | T1021.001 Remote Desktop Protocol | Lateral Movement | The spine of all nine days |
| 5 | T1046 Network Service Discovery | Discovery | Carries the segmentation argument missed three times |
| 6 | T1136.002 Domain Account | Persistence | Three accounts via `dsa.msc`, passwords never to expire |
| 7 | T1036.010 Masquerade Account Name | Persistence | `administratr`; a real name altered by one character |
| 8 | T1098.007 Additional Local or Domain Groups | Privilege Escalation | Domain Admins, and Group Policy Creator Owners |
| 9 | T1219.002 Remote Desktop Software | Persistence / C2 | AnyDesk on a DC, installed and never used |
| 10 | T1105 Ingress Tool Transfer | Discovery, day 6 | Cashes the egress argument left open in Cobalt Kitty |
| 11 | T1110.003 Password Spraying | Discovery, day 6 | NetExec over port 445 |
| 12 | T1560.001 Archive via Utility | Collection | 7-Zip right-click, staged on the Desktop |
| 13 | T1567 Exfiltration Over Web Service | Exfiltration | temp.sh. Taught at **parent** level, and why |
| 14 | T1518.002 Backup Software Discovery | Impact | Veeam console. One recorded group in all of ATT&CK |
| 15 | T1490 Inhibit System Recovery | Impact | Backup jobs deleted before encryption, not after |
| 16 | T1486 Data Encrypted for Impact | Impact | `w.exe --dir E:\ --mode fast --verbose --noprint` |

**Numbers are fixed at 16.** Anything else found is appended, never inserted - renumbering cost
the user their place three times on report 1.

**Named and skipped**, so the subset is not mistaken for the whole: T1059.003 Windows Command
Shell (callback to T1059.001 PowerShell); T1016 System Network Configuration Discovery, T1082
System Information Discovery, T1012 Query Registry, T1018 Remote System Discovery, T1057 Process
Discovery, T1087.002 Domain Account, T1069.002 Domain Groups, T1135 Network Share Discovery,
T1518 Software Discovery - the Discovery section is enormous and its decision content is not,
so the pattern is taught once at slot 5; T1039 Data from Network Shared Drive - the closest
call, folded into slot 12; T1074.001 Local Data Staging; T1078.003 Local Accounts; T1213 Data
from Information Repositories.

**Langue du cours, fixée 2026-08-24.** Le cours se donne **en français**. Instruction de
l'utilisateur : *"Le français pour tout le concours mais on peut garder les termes techniques en
anglais pour ne pas faire une traduction à outrance."* Donc :

- Corps du cours, explications, marking, questions de contrôle : **français**.
- **Restent en anglais** : les citations MITRE verbatim (c'est la citation qu'il reprend dans ses
  documents de conception), les noms de techniques, tactiques et mitigations, les noms de log
  sources et d'event IDs, et le vocabulaire technique courant du métier — beachhead, logon type,
  elevated token, gateway, MFA, segmentation, payload. Ne pas franciser à outrance.
- Les sept intitulés de sections sont traduits : *Ce que c'est* (avec **la frontière**), *Pourquoi
  l'adversaire le fait*, *Sur votre stack*, *Ce que l'attaquant a fait dans le rapport*, *Ce qui
  l'arrête*, *Ce qui le révèle*, *Contrôle*.

**La frontière — définition demandée deux fois le 2026-08-24, donc à énoncer clairement quand
elle sert.** Partie qui clôt la section 1. Elle nomme les techniques voisines avec lesquelles
celle-ci est confondue et donne, pour chacune, le seul fait qui tranche. Elle répond à *comment
sais-je que c'est celle-ci et pas celle-là*, pas à *qu'est-ce que c'est*. Enjeu : chaque voisine
porte un jeu de mitigations différent, donc se tromper de technique produit une exigence qui
sonne juste et vise le mauvais problème.

### Progress

- **1/16 pre-compromise** - delivered 2026-08-24. T1650 Acquire Access, T1588.002 Obtain
  Capabilities: Tool, T1583.003 Virtual Private Server. One open question, no MCQ set: the phase
  has no design decisions to test. M1056 Pre-compromise addresses **0 techniques in scope** -
  used as the concrete demonstration that no preventive control exists here.
- **2/16 T1133 External Remote Services** - re-taught in full (not a callback) 2026-08-24,
  because it was `shaky` and this report rests entirely on its control-boundary gap. Delivered
  in French. Carries two tactics, taught as a *state* not a step. Key content: logon type 3 then
  10 as one RDP connection; the `DESKTOP-BUL6K1U` Workstation name constant across both source
  IPs; M1032 Multi-factor Authentication as the control that *would* have stopped day one - the
  inverse of the T1078.004 Cloud Accounts case - with the boundary answer that it covers the
  first hop only, since the DC pivot ten minutes later never touches the gateway; M1021 Restrict
  Web-Based Content named as the inapplicable one. Five-question hybrid asked and marked
  2026-08-24: **`solid`**. Q1, Q3, Q4 correct unaided (boundary, inapplicable control, dual
  tactic as a state). Q2 was **defective and the user caught it** - the stem published RDP
  directly on the app server, then the options referred to a gateway that was never in the
  scenario. Re-asked cleanly as 2 bis and answered correctly: MFA covers the perimeter crossing
  only, internal domain-to-domain connections never re-evaluate it. That was the exact gap that
  made this technique `shaky` on 2026-08-10, so it is now closed.
- **3/16 T1078.002 Domain Accounts** - callback slot delivered 2026-08-24, **`shaky`** (was
  `solid`). Three of five correct: the four-tactic technique read as a *state* not a step (Q2),
  M1032 Multi-factor Authentication as the only one of the three credential-obtaining
  mitigations that bites when the credential was bought (Q3), and the domain admin account as a
  *reach multiplier* that turns a netscan into the day-9 encryption target list on day 1 (Q4,
  after the vocabulary was fixed). Two missed - see the two findings below.
- **4/16 T1021.001 Remote Desktop Protocol** - taught 2026-08-24, **`shaky`**. Four MCQ answered
  correctly but they carried the longest-option tell, so they are not evidence. On the open
  question the user reached **GPO logon-right groups unaided** - the first time in this session
  the bounding mechanism was produced rather than "remove the domain", which closes the first
  retest. Two misses: the question was about a **flow** rule and was answered with an identity
  control, so the network team still has no rule and a compromised support technician's account
  satisfies the GPO completely; and the explicitly requested residual half was not attempted.
  The teaching answer is to split the flow rule **by destination class** - workstation to
  workstation allowed (that is the entire support use case), workstation to server denied,
  server to server denied except from the defined administration path - which dissolves the
  objection, with the GPO layered on top rather than instead.
- **5/16 T1046 Network Service Discovery** - taught 2026-08-24, **`shaky`**. First slot under
  the new format (one open question, no MCQ) and **both halves of the two-part question were
  attempted** - the previous finding does not repeat. On (a), one of three elements landed: the
  dedicated non-human service account, correctly justified as making identity a discriminator.
  On (b), the core is right - the attacker gains reach to every server - but the two sharper
  consequences were missed: he inherits the **alibi** (scanning from that host is expected
  behaviour by policy) and the **finished inventory**, which in this report cost the attacker
  four separate scanning sessions to rebuild. Teaching answer for (a): a legitimate scan is
  distinguishable because it is *predictable*, pinned on window, source address, declared
  destination/port set and identity - each pin is a free detection rule. Design consequence: an
  inventory server is a Tier 0 asset nobody classifies as one.
- **6/16 T1136.002 Domain Account** - taught 2026-08-24, **`shaky`**. Part (a) answered; **(b)
  was never tested because I marked before the user had finished** - see the corrected finding
  below. Marked **`solid`** after the user pushed back on the group-membership point: they had
  meant the bounded privilege to include what the created account can be granted. Taken at their
  word, and the reason is stated - bounding a privilege rather than removing a capability is the
  mechanism they produced unaided at 4/16, so the clarification is consistent with demonstrated
  reasoning rather than a retrofit. On (a): OU-scoped delegation is right and is the main condition; and *"les
  journaux... non accessible par ceux qui créent les comptes"* is **the first time the "who must
  be trusted for this control to hold" reasoning was produced by the user**. Credit precisely -
  forwarding logs off the DC was in my own message, but restricting *read* access from the
  delegated team was not. Missed: the delegated right must exclude **group membership** (creating
  in your OU is bounded, adding to a group is not - and that is the report's own sequence), the
  declared account shape, the pipeline's own identity as a new account-creation authority, and
  reconciliation against declared pipeline runs.

  **AD mechanics worth reusing, from the pushback exchange.** Creation and membership are two
  ACEs on two different objects: *create user objects* sits on the **OU**, *write the `member`
  attribute* sits on the **group object**. So OU delegation genuinely does not grant Domain
  Admins - the user was right about that. But it does not bound membership either, and there are
  two concrete leaks: application groups living **inside** the delegated OU are covered by the
  delegation, so membership is delegated without being written down; and if any of those groups
  is itself nested in a privileged group elsewhere, adding a member confers the outer group's
  rights transitively while the OU boundary stays intact. **Nesting is the leak and it is
  invisible in the delegation diagram.**

  **The requirement-writing lesson:** "delegation limited to the application OU" will be
  implemented by the directory team as a user-object creation ACE on that OU and nothing else.
  What is not named is not implemented. The durable wording names both ACEs and forbids groups in
  the delegated OU from being members of any group outside it.
  Teaching content worth keeping: **ATT&CK's analytic DET0003/AN0006 requires step (1) a
  suspicious process such as `net user /add /domain`, then (2) Event ID 4720.** The attacker used
  `mmc.exe` with `dsa.msc`, so step (1) never fires while 4720 fires identically - analytics
  encode assumed tradecraft, not the technique. Specify the **state event**, never the route to
  it. And the answer to (b): accepting the delegation makes 4720 stop being rare, converting the
  report's best free signal into noise; the anomaly must be rebuilt as "an account no pipeline
  run claims".
- 7/16 onward not started. **Carries one retest**: the identity-scoping failure, and the
  detection cost of Tier 0 logon practice. T1021.001 Remote Desktop Protocol is the right place
  for both because logon rights are its native control.

**The 1/16 open question was dropped**, not answered - the user moved straight to initial access.
Its content (why "you can't defend against a bought password" does not end the argument) was
folded into the 2/16 open question instead.

**MCQ defect rule, 2026-08-24, caught by the user.** A question 2 was written whose stem
described RDP published directly on an application server, while its options turned on a gateway
that appeared nowhere in the stem. The user's response was *"La question est confuse."* They were
right. **Before asking an MCQ, re-read the stem and confirm every option refers only to
components the stem actually put in the scenario.** A defective question costs the assessment,
not just the exchange - and it is re-asked fresh, never patched in place.

**Method defect, 2026-08-24, caught by the user.** The session opened by running the
`dfir-report-walkthrough` skill - a socratic "you map the section first" format - for three
messages before `attack-learning/progress.md` was read. The user's correction was *"No no. You
missed everything."* **Read the progress file before the first substantive message of any
session**, not after a correction. The walkthrough skill and the tutor's report mode are
different products and this repo's user has settled on the tutor.

---

## The paused route: a tactic tour

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
| 1 | TA0001 initial-access | 21 | **done** 2026-08-10 |
| 2 | TA0002 execution | 48 | **done** 2026-08-11 |
| 3 | TA0003 persistence | 91 | opener given 2026-08-11, **paused here** for report mode |
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

### How many techniques per tactic

The user handed this decision to the tutor on 2026-08-10 — *"I don't [know] if it is the right
number. I will let you decide the most important techniques for each tactic."* The fixed three
was arbitrary: it applied the same count to a tactic with 17 techniques and one with 141.

**The rule: teach a technique when it carries a design decision you cannot get from another
technique in the same tactic.** Everything else is named and skipped in the opener, so a subset
is never mistaken for the whole. **Variation count is not decision count** — Stealth's 141
techniques are largely different ways to do about five things; Lateral Movement's 19 are
genuinely different problems.

| Tactic | Teach | Why |
|---|---|---|
| Initial Access (21) | 3 | On-prem has few doors: a person, an exposed service, a working credential |
| Execution (48) | 4 | Where on-prem intrusions live — scripting, WMI, client-side exploitation, user-run files |
| Persistence (91) | 5 | The one tactic where mechanism diversity *is* the lesson |
| Privilege Escalation (79) | 3 | Much of it is persistence reused; three distinct escalation ideas |
| Credential Access (58) | 4 | Memory, directory database, Kerberos, guessing — four different controls |
| Discovery (42) | 2 | High volume, low decision diversity. The *pattern* is the lesson |
| Lateral Movement (19) | 4 | Smallest tactic, second-largest allocation — the cloud track left it blank |
| Collection (32) | 2 | |
| Command and Control (45) | 3 | Protocol variations; the decisions are all egress design |
| Exfiltration (17) | 2 | |
| Impact (30) | 2 | Encryption, and the recovery inhibition that makes it work |
| Defense Impairment (34) | 3 | |
| Stealth (141) | 4 | Sampled hard, with an explicit statement of what is left out |

**41 techniques total.** Two deliberate inversions of tactic size: Discovery gets 2 from 42,
Lateral Movement gets 4 from 19.

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
the record and is not re-taught. **On-prem track from here:**

| Technique | Tactic | Taught | Status |
|---|---|---|---|
| T1566.001 Spearphishing Attachment | initial-access | 2026-08-10 | **solid** |
| T1133 External Remote Services | initial-access | 2026-08-10, re-taught 2026-08-24 | **shaky** |
| T1078.002 Domain Accounts | initial-access | 2026-08-10, callback 2026-08-24 | **shaky** |
| T1059.001 PowerShell | execution | 2026-08-11 | **solid** |
| T1204.002 Malicious File | execution | 2026-08-11 | **shaky** |
| T1047 Windows Management Instrumentation | execution | 2026-08-11 | **solid** |
| T1203 Exploitation for Client Execution | execution | 2026-08-11 | **solid** |
| T1566.002 Spearphishing Link | initial-access | 2026-08-11 | **solid** |
| T1053.005 Scheduled Task | persistence | 2026-08-11 | **shaky** |
| T1059.005 Visual Basic | execution | 2026-08-11 | untested |
| T1218.005 Mshta | stealth | 2026-08-11 | untested |
| T1021.001 Remote Desktop Protocol | lateral-movement | 2026-08-24 | **shaky** |
| T1046 Network Service Discovery | discovery | 2026-08-24 | **shaky** |
| T1136.002 Domain Account | persistence | 2026-08-24 | **solid** |

**T1078.004** — the boundary against T1528 and T1550 landed; **mitigation applicability did
not.** The check asked what MFA and Conditional Access buy you when a partner's CI/CD service
principal is breached, and the answer was that the attacker still needs the user's MFA device.
Not an open gap, though: the same applicability reasoning was reached **unaided** one technique
later on T1195.002. Retest it in tactic 2 rather than reteaching it.

---

## Findings

Observations worth keeping, recorded as they come up.

### Report track — Cobalt Kitty (2026-08-11)

**Paused 2026-08-11 — the user is reading the whole report first.** *"I think I should read the
whole report before learning techniques. It will give me the big picture."* Correct instinct and
it diagnoses the session's real problem: the report is a narrative, techniques are a
decomposition of it, and decomposing a document they had not yet read whole is why they lost
their place in the numbering three times and twice caught phase-1 gaps I had missed.

**Rule for report mode from here: the user reads the lifecycle section end to end before any
technique is taught.** Do not open a report by teaching from it.

Reading guide given: pages 1–32 in full; page 35 for the payload table; skip the arsenal.
Collect four things — control-defeat sentences, phase transitions, what each action presupposed,
and what cannot be told from the document. Do not map to ATT&CK while reading.

**On return:** ask a fresh check set; the five T1059.005 Visual Basic questions are dropped.
Then decide with them whether to continue technique by technique or restructure the curriculum
now that they have the whole picture — the order may want to change once they have seen it.

**Question format changed 2026-08-11**, at the user's request: *"for the question i prefer
multiple choice question and 5 by techniques."* Delivered as **four multiple-choice plus one
open**, with the reason stated plainly — MCQ tests recognition and boundary discrimination well,
and cannot test production, which is what an architect's output actually is and what was missed
on T1053.005 Scheduled Task. The user has not yet said whether they accept the hybrid or want
five MCQ. **Ask before the next check.**

MCQ rules: scenario stems, never definitions; distractors drawn from real ATT&CK content —
adjacent techniques and real mitigations that do not apply; no "all of the above"; all five in
one message so they can be answered in a single line; the marking explains why each wrong option
is wrong, which is where the teaching lives.

### Progress at the pause

- **1/15 T1566.002 Spearphishing Link** — taught, checked, `solid`
- **2/15 T1566.001 Spearphishing Attachment** — callback delivered
- **3/15 T1059.005 Visual Basic** — taught, check dropped, `untested`
- **4/15 T1053.005 Scheduled Task** — taught, checked, `shaky`
- **5/15 T1218.005 Mshta** — taught, check never answered, `untested`
- 6/15 onward not started

**T1566.002 Spearphishing Link — solid.** The check asked what click-time URL rewriting still
does not cover, given how the link path was built. Answer: *"The rewriting is just for the first
link in the mail. It doesn't apply to the link flash use to download the payload?"* Correct, and
reached without scaffolding beyond a definition of the term. **This is the first time the
control-boundary reasoning was produced unaided** — the same move that was missed at T1133
External Remote Services and at T1204.002 Malicious File.

Two beats not reached, both given: the redirector defeats click-time evaluation even at step 1,
because it serves different content to a scanner than to the victim's browser; and the same
campaign ran an attachment path with no link in it at all.

**The decomposition finding, which produced the answer.** One sentence of a report is several
techniques, because ATT&CK models behaviours rather than incidents. The link-to-beacon chain is
five: T1566.002 Spearphishing Link (TA0001) → T1204.001 Malicious Link (TA0002) → T1204.002
Malicious File (TA0002) → T1105 Ingress Tool Transfer (TA0011) → T1027.013 Encrypted/Encoded
File (TA0005). **Five techniques means five control opportunities, each owned by a different part
of the architecture**, and a mail gateway is present at one of them. Teaching the decomposition
first is what made the check answerable — do this at the start of every phase in a report.

**Jargon defect, 2026-08-11.** "Click-time URL rewriting" was used across two messages with no
gloss, and the user could not answer the check because of the term rather than the idea: *"I
don't know what is click time."* The rule against unglossed product terms already exists in
SKILL.md and was broken anyway. Product names (Safe Links, URL Defense) come *after* the
mechanism, never instead of it.

**Egress is the sentence to carry forward.** Between the click and Beacon in memory, the only
control positioned at the payload fetch is egress control. ATT&CK's mitigation set for T1105
Ingress Tool Transfer is M1031 Network Intrusion Prevention and M1037 Filter Network Traffic —
**no endpoint control at all.** Cash this in at 8/13 T1071.004 DNS.

**T1053.005 Scheduled Task — shaky.** A fresh check was asked after the third delivery (approve a
nightly batch job running as a domain service account with `db_owner` on the application
database). Answer: *"It should not run as domain account."* Wrong for the scenario — the job
reaches SQL Server over the network, and a local account has no identity off its own machine, so
the requirement makes the job impossible. The axis was right (constrain the reach of the
identity), the conclusion was not.

**This is a regression, and it is the same regression as before.** They produced *"privilege
management, tiering and use of managed service accounts is the control to have"* unaided during
the execution tactic, and did not reach for it here. The recurring diagnosis stands: general
tests are derived correctly and then not applied. Retest managed service accounts explicitly at
14/15 T1550.002 Pass the Hash.

**The residual they did not reach**, which is the real design content: after a gMSA, least
privilege in SQL, denied interactive logon, and non-writable script paths, **anyone with
administrator or SYSTEM on that host still has the account's database access** — SYSTEM can
retrieve the gMSA password by design. The server is the security boundary of the database.

**Earlier note, kept:** the first check on this technique was cancelled at the user's request on
2026-08-11, after being
carried across the two format corrections. Status stays `untested`; the technique itself was
taught twice, in full. Do not re-ask it as a standalone question — if the run-as account idea
needs testing, fold it into a later check (T1543.003 Windows Service is the natural place, since
it is the same axis with a different default).

**Process lesson:** a check question does not survive a format correction. If a message gets
re-issued or corrected, the question inside it is lost, whatever the transcript says. Ask it
fresh in its own message, or drop it.

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

### THE unifying diagnosis: the control is placed inside the boundary it must enforce (2026-08-24)

Four occurrences now, across both tracks, and they are the same move:

- **T1078.004 Cloud Accounts** - MFA imagined to cover a non-interactive workload identity.
- **T1552.001 Credentials In Files** - a managed identity imagined to restrict access from the
  application's own execution context.
- **T1053.005 Scheduled Task and T1133 External Remote Services** - "remove the account from the
  domain", i.e. delete the identity rather than bound it.
- **T1046 Network Service Discovery** - the scanning server *logs its own activity so the IPS
  can judge whether the scan is legitimate*, i.e. the audited tool certifies itself. (The
  plumbing is also wrong - an IPS reads traffic, not the scanned host's application log - but
  the plumbing is the smaller error.)

**The axis is reached unaided every single time.** What fails is mechanism selection, and it
fails in one consistent direction: the chosen control depends on trusting the very thing it is
supposed to constrain.

**The correcting question, to put to the user by name from here on: *qui doit être digne de
confiance pour que ce contrôle tienne ?*** If the answer includes the thing being controlled,
the control does not exist. This supersedes the narrower "identity scoping" framing recorded
below - that was one instance of this, not the pattern itself.

This is also the same shape as the telemetry question *can the party being audited disable the
audit?*, which gives a ready bridge when teaching it.

### Do not mark before the user has finished answering (2026-08-24, corrected by the user)

Twice now, an open question asking for two named things has come back with one.

- **3/16 Q5** said *"nommez le coût côté détection, pas seulement côté prévention"*. Only the
  prevention half came.
- **4/16** said *"nommez ce que votre découpage ne couvre plus"*. Only the découpage came.

**The content produced is sound in both cases; it is the reading of the instruction that drops
out.** Distinct from the identity-scoping failure, which was a wrong mechanism - here the
mechanism is right and a requested part is simply absent.

**This finding was largely wrong and the user corrected it**: *"J'allais repondre à la deuxième
après la première mais bon."* They answer in successive short messages, and I treated the end of
a message as the end of the answer, then marked a half as missing when it had simply not been
sent yet. The 3/16 and 4/16 instances are suspect for the same reason and should not be treated
as a demonstrated reading failure.

**Rule: wait for the user to finish before marking.** If an answer looks partial, ask whether
they are done rather than scoring it.

**Format settled 2026-08-24, on the user's call: one open question per technique, full stop.**
Their reasoning, which is correct: the same techniques recur across reports, so drilling a second
angle on one slot costs more than it returns - the second angle arrives on its own with the next
victim and the next architecture.

### A check must not be answerable from the message that contains it (2026-08-24)

*"Pourquoi la suggestion du prompt me propose deja la reponse. C'est embetant en mode
apprentissage."* The client's suggested-reply feature was handing the user the answer. That
feature is not controllable from here, but **half the cause is mine**: those suggestions are
generated from my own message, so when section 5 explains what stops the technique and section 7
then asks what stops the technique, the answer is sitting in the same message and any suggestion
engine will lift it.

**Rule: the check question must not be answerable by re-reading the message it closes.** It has
to require *applying* the content to a situation not covered above - a constraint not addressed,
a colleague's objection, a trade-off between two mitigations that were never compared. If the
answer can be found by scrolling up, the question tests nothing, screen suggestion or not.

Also avoid putting the check in the same message as a long recap of the very material it tests;
proximity helps even when the wording does not.

### The MCQ instrument was broken: longest option = correct answer (2026-08-24, caught by the user)

*"Les qcm sont mal élaborés. Il suffit de voir la reponse la plus longue qui correspond à la
reponse exacte. J'ai répondu presque à l'aveugle."* Audited across every MCQ asked in this
report: **the correct option is the longest in 11 of 12 questions.** The one exception is Q1 of
2/16.

**Root cause, and it is a method fault rather than luck.** The correct option was being written
as a piece of teaching - it carried the reasoning, the nuance, the "because" - while the
distractors were bare assertions. The shape gave the answer away, so the instrument measured
word-counting.

**Rule from here.** Options homogeneous in length, roughly within 10% of each other. Every
distractor carries reasoning too, drawn from real ATT&CK content - a plausible adjacent
technique, a real mitigation that does not apply here. No obviously absurd option (a "netscan is
malware, block it with antivirus" filler appeared at 4/16). And decisively: **the correct answer
teaches nothing** - teaching belongs in the marking reply, never in the option to tick. Check
before sending: re-read the four options with correctness forgotten, and confirm none can be
picked by shape.

**What this invalidates.** T1133 External Remote Services had been promoted to `solid` on the
strength of question 2 bis, an MCQ carrying the tell - **reverted to `shaky`**. The claim written
in the 4/16 marking that "boundary discrimination is acquired across the four axes tested" is
withdrawn: not disproven, but unfounded, which is worse for the learner. T1078.002 Domain
Accounts stays `shaky` on its own merits - what it missed was missed on the **open** question.

**What does count as evidence in this session**, because it is free production rather than
selection: the 2/16 open answer reaching the right axis unaided (bound what the credential can
reach), and the unprompted question about the created accounts being Domain Admins, which
corrected a real error in my tiering reasoning. No MCQ would have surfaced either.

**Standing consequence:** weight status decisions on the open question and on free exchanges.
An MCQ set alone is not sufficient to move a technique to `solid`.

### Tiering assumes the attacker is not already Tier 0 (2026-08-24, correction caught by the user)

**A wrong claim was made and the user caught it.** Explaining logon rights during 4/16, I listed
"days 2, 8 and 9" as what *Deny log on locally* / *Deny log on through Remote Desktop Services*
would have blocked in this report. The user asked: *"Les comptes qu'il a créé ne sont ils pas
administrateur de domaine?"* They are - the report puts `administratr` and `Lookalike 1` in
**Domain Admins**, and day 2 is those accounts logging on to hypervisors, i.e. Tier 0 accounts
on Tier 0 machines. Tiering permits that by construction.

**Corrected, hop by hop.** Of every pivot in the intrusion, logon-right tiering blocks exactly
one: the day-9 RDP sessions to the **file servers**, Tier 1 machines reached with a Tier 0
account. Day 1 to the DC, day 2 to the hypervisors, day 8 to DCs and hypervisors, day 9 to the
backup servers - all Tier 0 accounts to Tier 0 machines, all inside the rule.

**The structural lesson the question exposed, worth more than the correction.** Tiering assumes
the adversary is not already in Tier 0. This one arrives holding a bought domain admin
credential, so he never crosses the boundary - he starts inside it. Then on day 1 he *settles*
there, creating his own Domain Admins members so he no longer depends on the purchased one.
That is why the report contains no privilege escalation in the technical sense: no exploit, no
token theft, no credential dumping. Its Privilege Escalation section is group additions only,
because there was nothing to escalate.

**Consequence to teach at 8/16 T1098.007 Additional Local or Domain Groups:** a control that
sorts identities by level is worth exactly what the control on *entry into the top level* is
worth. The questions become how many accounts hold Domain Admins, who may add one, and whether
that addition alerts. Group membership addition is logged natively - `WinEventLog:Security` EID
4728 (global group) and 4732 (local group) - one of the few events in this report that is free,
rare in normal operation, and decisive.

For day 1, before he made himself a domain admin, the control that bites is still segmentation
on **outbound initiation** from the beachhead - the only one on the list that does not depend on
which identity is used.

**Process note:** this is the second substantive catch by the user in one session (after the
defective MCQ). Both came from checking a claim against the report's own text. Do that before
asserting what a control would have blocked - walk it hop by hop, not by category.

### Forensic density is evidence that the telemetry existed (2026-08-24, from T1078.002)

Q1 asked what to conclude from the report finding no credential access activity in nine days.
Answer: *"La télémétrie manquait pour observer un dump de credentials."* Wrong, and the report
refutes it by its own evidence density - Sysmon EID 3 network connections, EID 11 `delete.me`
file creations on remote shares, Security EID 5145 share access, EID 4688 command lines, and
reconstructed images from the **RDP bitmap cache**. An environment instrumented to that level
does not miss LSASS access.

**The transferable principle:** a report that reconstructs an intrusion in forensic detail is
*proving* the telemetry existed, so its stated absences are observed absences, not blind spots.
Distinguishing *"we saw nothing"* from *"there was nothing"* is what separates reading a report
from paraphrasing it. This is the move that licenses the report's own conclusion - the domain
admin credentials were held before the intrusion.

### Prevention was given where detection was asked for (2026-08-24, from T1078.002)

Q5 asked what it costs when sysadmins RDP to an application server with Domain Admins accounts,
and said in the stem to name **the detection cost, not only the prevention cost**. The answer
covered lateral movement only - the prevention half, correctly, and nothing else.

**The content that was missed had been taught in section 6 of the same message.** If Domain
Admins logons to that server are routine, the attacker's 4624 is indistinguishable from yours:
there is no baseline left to violate and no tool restores it, because the information is not in
the log. The inverse is the design lesson - **restricting where Tier 0 accounts may log on
manufactures detectability**. Once the rule exists, any Domain Admin logon on a Tier 1 server is
an anomaly by construction, and a single event becomes an alert instead of noise you created
yourself. A preventive control that produces signal by existing, with no product purchase.

Related to but distinct from the identity-scoping failure below: there the mechanism was wrong,
here the requested half of the question was not attempted.

### Vocabulary defect, 2026-08-24 - French edition of the "click-time" failure

Question 4 could not be answered because of one word: *"que signifie inscriptible"*. The word
was my own French rendering of "writable" and it blocked the question, exactly as "click-time
URL rewriting" did on 2026-08-11. **In French, prefer plain phrasing over a clever equivalent:
"accessible en écriture", not "inscriptible".** The rule against unglossed terms already existed
and was broken again in a new language. Re-asked as 4 bis after glossing, and answered correctly
- the term was the obstacle, not the idea.

Gloss that worked, kept for reuse: netscan tests write access by dropping a file named
`delete[.]me` on each discovered share and deleting it (Sysmon EID 11, Security EID 5145). With
domain admin rights the test succeeds everywhere. **A readable share gets stolen; a writable
share gets encrypted.**

### The recurring failure: the general test is derived, then not applied (2026-08-24)

**Second occurrence of the identical wrong answer.** Asked at 5 bis of T1133 External Remote
Services to name one design decision, other than MFA, that limits what a valid domain account
yields once the attacker is on a domain-joined Tomcat server, the answer was *"L'accès ne
devrait pas être donné au domaine"*. On T1053.005 Scheduled Task the answer had been *"It should
not run as domain account"*, wrong for the same reason.

**The axis is produced unaided every time** - *"on doit être capable de contrôler ce que
l'attaquant ayant ce mot de passe peut faire sur nos serveurs"* is the correct question, reached
without scaffolding. **The mechanism named is wrong in the same way every time: the identity is
removed instead of being bounded.** Removing domain membership does not constrain the reach of
an identity; it deletes the identity, and with it central management, patching and central
logging. It also answers a different question from the one asked - both scenarios asked what
limits the account *after* the attacker is already on the host.

**What was available and not reached**, all previously taught: M1026 Privileged Account
Management as logon-right tiering (*Deny log on through Remote Desktop Services* / *Deny log on
locally* for Tier 0 accounts on application servers, and application-server admins who are not
Domain Admins); M1030 Network Segmentation on *outbound* initiation from the application server
- the strongest answer here, since the report's beachhead-to-DC pivot takes ten minutes and
presupposes only permission to connect; a gMSA scoped to its own database with interactive logon
denied.

**The residual, given twice now and still not produced back:** anyone with administrator or
SYSTEM on the host has whatever that host's identities can reach - SYSTEM retrieves a gMSA
password by design. The server is the security boundary of what it accesses.

**Retest explicitly**, and phrase it so that "remove the domain" is not an available move: at
**4/16 T1021.001 Remote Desktop Protocol**, where interactive logon rights are the native
control. The T1550.002 Pass the Hash retest planned for report 1 never happened - that report
closed at 5/15.

### On-prem track

### Tactic 2 close — execution, on-prem (2026-08-11)

**Three ways to get code running, only one involving a vulnerability.** T1059.001 PowerShell and
T1047 Windows Management Instrumentation abuse **signed Microsoft components you installed on
purpose**; T1204.002 Malicious File abuses **the user**; T1203 Exploitation for Client Execution
abuses **a bug**. Three control families — constrain the tool, remove the decision, patch or
sandbox — and specifying the wrong family is this tactic's failure mode.

**M1049 Antivirus/Antimalware appears once in four techniques** (T1059.001 PowerShell, and there
only partially via the Antimalware Scan Interface). An execution-phase story of "we have endpoint
antivirus" covers roughly a quarter of one technique.

**Unlike every earlier tactic, one mitigation genuinely spans this one.** **M1038 Execution
Prevention** — application control — is on three of four, doing a different job in each:
Constrained Language Mode against PowerShell, blocking what a `.lnk` launches, constraining what
WMI starts. **M1040 Behavior Prevention on Endpoint** covers two. Application control in
enforcement mode is the highest-value on-prem investment in this tactic and carries the largest
operational cost, which is why it usually does not happen.

**One telemetry decision serves all four: process ancestry.** Every technique signals the same
way — what spawned what. Requires Sysmon or Windows process-creation auditing with command lines,
**both off by default**, forwarded from workstations and member servers, which is exactly where
most estates do not collect. One decision, four techniques — that is the budget argument.

**Taught:** T1059.001 PowerShell, T1204.002 Malicious File, T1047 Windows Management
Instrumentation, T1203 Exploitation for Client Execution. **Named and skipped:** T1059.003
Windows Command Shell (91 groups — highest-usage technique skipped anywhere, deliberately: same
design decisions as PowerShell); T1059.005 Visual Basic, T1059.007 JavaScript, T1059.006 Python,
T1059.004 Unix Shell (covered by the macro policy and the same controls); T1106 Native API (an
evasion refinement — it is what an adversary moves to when PowerShell is constrained, so it
measures what that control bought); T1072 Software Deployment Tools (strongest fifth candidate —
belongs with the privilege discussion); T1574 Hijack Execution Flow and T1053 Scheduled Task/Job
(carry persistence, taught there); T1197 BITS Jobs, T1129 Shared Modules, T1559 Inter-Process
Communication, T1674 Input Injection (narrow).

**T1203 exposure findings:** client **applications**, not the OS, are the gap — and the CVE lists
name them (Office, Adobe Reader and Flash, WinRAR, Internet Explorer and Edge, Java); the worst
patched sit outside the standard build, so **you cannot patch what you do not know is installed**
(third appearance of the inventory idea after T1133 External Remote Services). "Office is
patched" can be true while the vulnerable component is not — `CVE-2017-11882` was in Equation
Editor, which Microsoft eventually removed rather than fixed. Second exposure, not named in the
answer: **the zero-day**. A patch SLA assumes a patch exists; **M1048 Application Isolation and
Sandboxing** is what remains standing when it does not. **Read the CVE numbers, not the group
names** — `CVE-2012-0158` and `CVE-2017-11882` recur across unrelated groups for a decade, so
client exploitation is overwhelmingly old patched bugs rather than zero-day work.

**For any protocol you cannot disable, ask three questions: who, from where, and to do what**
(2026-08-11, from T1047 Windows Management Instrumentation). The check — monitoring uses WMI
estate-wide, so it cannot be restricted — was answered with the *who*: restrict WMI to the
monitoring service account, and do not make that account privileged. Correct, and the
service-account lesson from T1078.002 Domain Accounts was transferred unprompted. Two additions.
**WMI namespace permissions are not a boundary** — remote WMI execution already requires local
administrator on the target, and a local administrator can rewrite those permissions; the real
gate is which accounts hold local admin across the estate. And **the missing half is again the
network one** (third time, after T1133 External Remote Services and the jump host): restrict
inbound **135** and **5985** by host firewall to the monitoring servers' addresses. Monitoring
keeps working; a compromised workstation cannot reach WMI on any server at all, and that holds
even when the attacker obtains an administrative credential, because there is no path to
authenticate over. Third layer: **M1040 Behavior Prevention on Endpoint** — block the WMI
provider host from spawning shells.

**M1038 Execution Prevention is weak against T1047 specifically** (2026-08-11). Application
control governs which binaries may run; WMI is serviced by an already-permitted signed Windows
process, so application control constrains **what WMI starts**, not WMI. Also worth holding: one
action — "run a command on that server" — spans **T1047 Windows Management Instrumentation**
(execution), **T1021.003 Distributed Component Object Model** or **T1021.006 Windows Remote
Management** (transport, lateral movement), and often **T1550.002 Pass the Hash**
(authentication). Three techniques, three different controls: endpoint, firewall, credential.

**Training is a detection control here, not a prevention control** (2026-08-11, from T1204.002
Malicious File — the check was answered with extension filtering correctly rejected and **user
training recommended in its place**, which is the control this technique is built to defeat).
FIN7's victims "double-click[ed] on **images** in the attachments"; Kimsuky used "LNK files
disguised with tailored filenames and fake extensions". Training teaches people to recognise
signals; **T1036 Masquerading** exists to remove the signals. Both extension filtering and
training are the same losing move — enumerating badness, once at a gateway and once in a human's
head under time pressure. What answers it: **M1040 Behavior Prevention on Endpoint** (attack
surface reduction — *block Office applications from creating child processes*, *block executable
content from email clients*), which acts on **behaviour rather than format** and is therefore
indifferent to whichever extension is invented next; behind it **M1038 Execution Prevention**,
since a `.lnk` runs a command and application control constrains what that command may start.
Training's legitimate role is **reporting** — a user who says "I opened something odd" hands over
an incident that would otherwise surface in three months.

**Pattern to work on: the general test is derived correctly and then not applied** (2026-08-11).
*What does this control do after the assumption it depends on has failed?* — produced unaided at
T1566.001 Spearphishing Attachment when choosing account management over training. Not reached
for at **T1133 External Remote Services** (front-door answers only, segmentation missed) and not
reached for at **T1204.002 Malicious File** (training recommended, whose assumption is that the
user can tell). The knowledge is there; the reflex is not yet. Retest by asking for the
assumption behind a named control rather than for the control.

**PowerShell execution policy is not a security control** (2026-08-11, from T1059.001
PowerShell). `RemoteSigned` and `AllSigned` exist to stop users running scripts by mistake, and
Microsoft documents them that way. Bypassed by a command-line switch, by piping to standard
input, or by an encoded command. **M1045 Code Signing** appearing on this technique's mitigation
list does not make execution policy an answer. **M1042 Disable or Remove Feature or Program** is
equally hollow — Windows and your own operations depend on PowerShell, and an adversary can host
the engine inside their own executable without launching `powershell.exe`, so blocking the binary
blocks the name rather than the capability.

**The control that works is application control, for a side effect** (2026-08-11). Windows
Defender Application Control or AppLocker **in enforcement mode** puts PowerShell into
**Constrained Language Mode**, removing the type and API access most offensive tooling needs
while leaving ordinary administrative scripting intact. Ask for that by name — "block code
execution" is a wish, this is a testable requirement. **M1026 Privileged Account Management**
closes it: a script does what the account running it can do.

**PowerShell has the best telemetry story in the on-prem foundation, with two conditions**
(2026-08-11). **Script block logging** records executed content **after deobfuscation**, so
encoded scripts (APT29's procedure) land in the log as readable text. It is **off by default**,
enabled by Group Policy, and must be forwarded off the host — an administrator can disable it,
which is **T1685 Disable or Modify Tools**, used by Akira. Second condition: that logging arrived
in PowerShell v5, so **PowerShell 2.0 must be removed from the estate** or an adversary can
request the old version and execute unrecorded. And the Antimalware Scan Interface does give the
scanner sight of script content at execution after decoding — routinely bypassed, so not a
control to rely on, but the reason encoding alone does not buy invisibility.

### Tactic 1 close — initial-access, on-prem (2026-08-10)

**Three doors, none of them broken.** A person opened an attachment (T1566.001 Spearphishing
Attachment); a published service accepted a login (T1133 External Remote Services); a valid
credential authenticated (T1078.002 Domain Accounts). No cryptography defeated, no protocol
subverted — everything worked as designed.

**MFA splits the tactic in half, and that split is the on-prem lesson.** Decisive at T1133
External Remote Services — a human at a prompt, and Akira's whole model defeated by it. Nearly
absent at T1078.002 Domain Accounts — Kerberos and NTLM authentication to a file server has no
second factor and no prompt. **"We have MFA" is true of the perimeter and false of the
interior**, and internal credential abuse lives in the interior. Expect to correct that claim.

**No single mitigation spans the three** (7, 5 and 5; M1018 User Account Management covers two,
M1032 Multi-factor Authentication covers two). What spans them is a property, not a control:
**the damage is set by what the compromised identity could reach, and from where** — the same
conclusion the cloud track reached from entirely different data, which is why it is worth
trusting.

**Taught:** T1566.001 Spearphishing Attachment, T1133 External Remote Services, T1078.002 Domain
Accounts. **Named and skipped, with reasons:** T1190 Exploit Public-Facing Application (65
groups, already solid; on-prem it is a server you patch yourself); T1189 Drive-by Compromise
(browser hardening; T1203 Exploitation for Client Execution teaches the structure better);
T1199 Trusted Relationship (design lesson duplicated by the partner-pipeline case at T1078.004
Cloud Accounts); T1195 Supply Chain Compromise (T1195.002 already solid); T1091 Replication
Through Removable Media and T1200 Hardware Additions (physical presence); T1669 Wi-Fi Networks
and T1659 Content Injection (network-layer, thin evidence).

**T1078.002 Domain Accounts, from the check:** password length prices the *guessing* attack and
nobody is guessing — the credential is resident in memory on every server the service runs on,
read via **T1003.001 LSASS Memory** or reused as a hash without recovering plaintext. Two
additions to the answer given: the account's security is **the security of the least
well-protected of the forty servers**, and **annual rotation is a dwell-time control that loses**
to intrusions running for months. Order the controls — group Managed Service Accounts fix *who
knows the password* and do not stop memory theft or change privilege; **removing Domain Admins is
what changes the blast radius.**

**Evaluate a control by what it does after the assumption it depends on has failed**
(2026-08-10, from T1566.001 Spearphishing Attachment). Of that technique's seven mitigations,
**M1017 User Training** depends on vigilance, **M1031 Network Intrusion Prevention** and the mail
gateway depend on the file being scannable, **M1049 Antivirus/Antimalware** depends on the
payload being known — and the procedures document each being defeated on purpose (APT-C-36 used
"password protected RAR attachments to avoid being detected by the email gateway"). **M1018 User
Account Management** is the only one that acts *after* the phish succeeds. It depends on nothing.

**A network boundary stops packets, not credentials** (2026-08-10, raised by the user asking why
a phished domain administrator matters when there is a boundary between the intranet and the
server network). Credential material for any account logged into a machine sits in memory on
that machine — **T1003.001 LSASS Memory** — so the credential comes to the attacker rather than
the attacker crossing to it. And the boundary already carries an exception for administration:
if the admin administers servers from that workstation, a rule permits RDP/WinRM/SMB along that
path, and the attacker uses it as an authorised credential on an authorised route. They need not
even steal the password — **T1134 Access Token Manipulation** lets them ride the existing logon
session. **The design-review question is not "is there a boundary?" but "which accounts can log
into machines on both sides of it?"** Any account that spans the boundary is the tunnel. The
user's reasoning is correct only under full tiered administration: separate accounts, the admin
account barred from user workstations by enforcement rather than convention, and administration
performed from a Privileged Access Workstation with no route from the user network to the
servers. Most organisations have the first, believe they have the second, lack the third.

**Segmentation is transitive; firewall rules are not** (2026-08-10, from the T1133 External
Remote Services revision check). A VPN segment permitted to reach exactly two destinations —
a file server and the administrators' jump host — is not limited to two things. Its real reach is
the file server **plus everything the jump host reaches**, one hop later. The metric is never
"how many destinations does this segment touch" but **"what is the transitive reach of those
destinations"**, which almost nobody computes; jump hosts, monitoring servers and backup servers
are the three machines that quietly undo most network designs. The rule also exposes the jump
host's **login surface** to every VPN session — password spraying, an exploit against RDP or SSH,
or a simple login with a stolen administrator credential, none of which MFA on the VPN affects,
because that already succeeded. Fix: administrative access originates from a separate dedicated
path, so the jump host is not reachable from the ordinary remote-user network at all.

**Separate accounts stop credential reuse, not credential capture** (2026-08-10, from the user
pushing back twice on the jump-host scenario — correctly). Using a distinct admin account for the
jump host does defeat the simplest path: the compromised user account has no rights on it. Two
things survive. **The login surface stays exposed** to every VPN session — password spraying,
credential stuffing and pre-authentication vulnerabilities in RDP or SSH care nothing about which
accounts exist; a service reachable by 400 remote users differs from one reachable by 12 admin
workstations under identical account controls. **And both accounts are used from one device**, so
the admin credential is typed on a machine that reads email — captured by keylogging, or the
session ridden via **T1134 Access Token Manipulation**.

**The separate-workstation requirement is tier 0 only, and the user was right to push back on it**
(2026-08-10). Two machines per administrator is not proportionate for ordinary server
administration. For tier 1 the requirement is narrower — *the admin credential must not be
replayable by whoever captured it* — and three controls deliver that without a second device:
**hardware-bound credentials** (smart card or FIDO2; keylogging yields nothing), **Restricted
Admin / Remote Credential Guard for RDP** plus Credential Guard on the workstation (no reusable
material sent to or left on the target), and **just-in-time privilege** with check-out and
rotation on release (a captured credential expires in minutes). What none of them closes is
**session hijack** — hardware credentials stop capture, not an attacker riding the authenticated
session. That residual is the only thing a separate machine buys, which is why it is reserved for
the tier where the residual is unacceptable. For tier 1, accepting it with hardware credentials
and just-in-time privilege in place is a defensible decision — documented as a risk acceptance,
not a gap. **The firewall rule remains free either way**: making the jump host reachable only
from an admin segment costs no hardware, no product and no user friction.

**This is the same conversion shape, now seen four times** (2026-08-10). Key Vault control plane
→ data plane; Microsoft Graph directory permission → Azure resource permission; Azure role →
Kubernetes cluster-admin; network segment → full reach via a permitted intermediary. **Privilege
and reach convert through whatever sits between.** The recurring review question: *can this
identity, or this segment, become one that has what it lacks?* This is the idea to retest — more
than any individual technique.

**Front-door controls versus what the session reaches** (2026-08-10, from T1133 External Remote
Services). The check asked what MFA and patching do not answer. The answers given — is the
MFA-exempt account list revoked (correct and sharp; it is exactly Akira's model), and can access
be restricted by location (**M1035 Limit Access to Resource Over Network**) — both stay at
authentication. Missed: **M1030 Network Segmentation**, the only mitigation on that technique
that changes the outcome *after* authentication succeeds, and the persistence half — Scattered
Spider used Citrix and VPNs *to persist*, so remote-access credentials must be reset during
incident remediation or rebuilding hosts ends nothing. Also missed: **M1042 Disable or Remove
Feature or Program** — you cannot enforce MFA on a service you do not know you publish.
Terminology note for the on-prem track: *Conditional Access* is an Entra ID product; the
on-premises equivalents are gateway source-address and geolocation restrictions, network access
control, or a device certificate requirement.

**Privilege separation is per account, not per person** (2026-08-10). "Only admins have admin
rights" is circular. The form that works: domain administrators hold a **second** account for
administration which never receives email or browses the web, and administration happens from a
separate workstation. The catastrophic case for T1566.001 Spearphishing Attachment is not the
finance clerk — it is a domain administrator opening an attachment on the account they
administer with, which is a full domain compromise in one step. Second, separate decision: what
an ordinary domain account can *reach* — file shares, internal applications, databases that
trust a domain login. Capping privilege and capping reach are different controls.

**One email, three techniques, three owners** (2026-08-10). **T1566.001 Spearphishing
Attachment** is delivery (initial-access); **T1204.002 Malicious File** is the person opening it
(execution); **T1203 Exploitation for Client Execution** is the file exploiting the reader
instead of asking for cooperation. Review consequence: if the payload needs macros enabled, the
macro policy is a control; if it exploits the PDF parser, it is not and patching is.

**Sysmon is not installed by default** (2026-08-10). The signal for T1566.001 Spearphishing
Attachment is not the email but the mail client's child process — Word or Outlook spawning a
command interpreter. ATT&CK's analytics lean on `WinEventLog:Sysmon`, which is a deployment
somebody must fund, and Windows' built-in process-creation auditing with command lines is off
until enabled by policy. **The evidence for the most-used technique in the framework does not
exist on a stock Windows estate.**

### Cloud track

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
