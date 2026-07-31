# ATT&CK learning progress

The tutor reads this at the start of a session and updates it as you go. You can edit it freely.

**Role context:** security architect designing security solutions and controls for application
projects. Learning ATT&CK to justify controls, specify telemetry, and pressure-test designs.
Not a detection engineer.

**Stack scope:** Cloud (IaaS/SaaS), Identity Provider, Containers, Linux/Windows servers.
581 of 697 Enterprise techniques are in scope.

---

## Status

Not started. Say **"start the guided path"** to begin.

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
| 1 | T1078 | Valid Accounts | 56 | ☐ |
| 2 | T1566.002 | Spearphishing Link | 55 | ☐ |
| 3 | T1189 | Drive-by Compromise | 34 | ☐ |
| 4 | T1110 | Brute Force | 17 | ☐ |
| 5 | T1078.004 | Cloud Accounts | 13 | ☐ |
| 6 | T1110.003 | Password Spraying | 13 | ☐ |
| 7 | T1199 | Trusted Relationship | 13 | ☐ |

## Covered

_Nothing yet._

<!-- The tutor appends entries here as: date — ID Name — one line on what mattered, plus
     anything you flagged as confusing so it can be revisited. -->

## Open questions

_Things to come back to._
