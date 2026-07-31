# The ATT&CK mental model

Read this when the user asks a framing question, or when they seem to be forming a wrong model
of what ATT&CK is.

## The one-sentence version

ATT&CK is a catalogue of **things attackers have actually been observed doing after they have a
foothold**, organised by what the attacker was trying to achieve.

The emphasis matters. It is descriptive, not prescriptive — it records what happened in real
intrusions, published by MITRE from public reporting. It is not a standard you comply with.

## The hierarchy

| Level | ID | Question it answers | Count (Enterprise v19) |
|---|---|---|---|
| **Tactic** | `TA0006` | *Why?* The adversary's goal at that moment | 15 |
| **Technique** | `T1003` | *How?* The general method | 196 top-level in the user's scope |
| **Sub-technique** | `T1003.001` | *How, specifically?* A named variant | 385 in scope |
| **Procedure** | — | *Who did it exactly how?* One group's implementation | thousands, as `uses` relationships |

Analogy that works for architects: the tactic is the requirement, the technique is the design
pattern, the sub-technique is the specific implementation, and the procedure is one vendor's
build of it.

**Techniques belong to multiple tactics.** T1078 Valid Accounts sits under four — initial
access, persistence, privilege escalation and stealth — because stolen credentials serve all
four goals. This trips people up. A technique is not "a step"; it is a capability that can be
used at several points.

## The 15 tactics, in rough chronological order

Not a strict sequence — real intrusions loop, skip and run several in parallel.

| ID | Tactic | The adversary is trying to… |
|---|---|---|
| TA0043 | Reconnaissance | gather information before touching you |
| TA0042 | Resource Development | build or buy infrastructure to attack from |
| TA0001 | Initial Access | get in |
| TA0002 | Execution | run their code |
| TA0003 | Persistence | survive a reboot, a password reset, a redeploy |
| TA0004 | Privilege Escalation | gain higher permissions |
| TA0005 | **Stealth** | avoid being seen |
| TA0112 | **Defense Impairment** | break or blind your security controls |
| TA0006 | Credential Access | steal account names and passwords |
| TA0007 | Discovery | work out what your environment contains |
| TA0008 | Lateral Movement | move to other systems |
| TA0009 | Collection | gather the data they came for |
| TA0011 | Command and Control | talk to compromised systems |
| TA0010 | Exfiltration | get the data out |
| TA0040 | Impact | destroy, encrypt or manipulate |

**Version note.** In ATT&CK v19, TA0005 is named **Stealth** — it was called *Defense Evasion*
for years, and most blogs, tools and vendor slides still say that. TA0112 **Defense Impairment**
is new, splitting "actively breaking your controls" out from "quietly avoiding them". If the
user has read older material, this discrepancy is worth one sentence.

The first two tactics (Reconnaissance, Resource Development) happen on the `PRE` platform —
outside your systems. They will show zero techniques in an application-platform scope, which is
correct, not a bug.

## The other object types

- **Mitigation** `M1032` — a preventive control. There are only 44 active ones, which is the
  useful surprise: the whole 697-technique catalogue is held down by a few dozen controls.
- **Detection Strategy** `DET0080` and **Analytic** `AN0219` — added in recent versions.
  A strategy groups analytics; an analytic names the concrete log sources and the correlation
  logic. This is where "what must my app log" comes from.
- **Data Component** / **Data Source** — the abstract telemetry categories (Process Creation,
  Cloud Service Modification) that analytics draw on.
- **Group** `G0016` and **Campaign** `C0032` — named adversaries and specific intrusion sets.
  Their `uses` relationships are what makes "56 groups do this" possible.
- **Software** `S0154` — malware and tools.

## What ATT&CK is NOT

This is the most valuable section for an architect. Getting these wrong produces expensive,
useless security programmes.

- **Not a checklist.** You cannot "cover" 697 techniques, and no one does. Attempting it
  produces coverage theatre.
- **Not risk-ranked.** ATT&CK does not tell you which techniques matter *to you*. T1078 and some
  obscure technique sit at the same level in the catalogue. Prioritisation is your job — the
  usage counts in this toolkit are a proxy for prevalence, not for your risk.
- **Not a maturity model.** "We're at 60% ATT&CK coverage" is close to meaningless: coverage of
  what, detected how well, at what false-positive rate?
- **Not exhaustive.** It records what has been *publicly reported*. Absence is not evidence of
  impossibility, and the catalogue is biased toward what well-instrumented Western enterprises
  detected and wrote up.
- **Not mostly about your application code.** ATT&CK is overwhelmingly about post-compromise
  behaviour. For "how does the flaw get in" you want threat modelling and OWASP; ATT&CK largely
  begins at T1190 and describes everything after.
- **Not a replacement for threat modelling.** It tells you what adversaries do in general; it
  knows nothing about your trust boundaries, your data flows or your business logic.

## How it relates to frameworks the user already knows

- **STRIDE / threat modelling** — STRIDE asks what could go wrong with *this design*. ATT&CK
  says what attackers actually do once something has. Use STRIDE first, ATT&CK to pressure-test
  and to name what happens after the first failure.
- **OWASP Top 10** — mostly upstream of ATT&CK. The Top 10 is how the vulnerability exists;
  T1190 is the moment it gets exploited; everything after is ATT&CK's territory.
- **ISO 27001 / SOC 2** — control catalogues, organised for auditability. ATT&CK is organised by
  adversary behaviour. ATT&CK is what you use to argue a control is *worth having*; ISO is how
  you evidence you have it.
- **CIS Controls** — the closest cousin; CIS publishes ATT&CK mappings. CIS says do this;
  ATT&CK says here is who beats you if you do not.
- **Cyber Kill Chain** — the ancestor. Seven linear phases; ATT&CK is the non-linear,
  far more detailed successor.
