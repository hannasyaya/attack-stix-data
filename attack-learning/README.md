# ATT&CK learning toolkit

A set of Claude skills that turn this repository into a tutor for MITRE ATT&CK, aimed at a
security architect who designs controls for application projects — not at a detection engineer.

You do not run any of this by hand. You talk to Claude; the skills do the rest.

## Try it

Open this repo with Claude Code and say:

- **"Start the guided path"** — begin the curriculum, three techniques at a time
- **"Explain T1190"** — one technique, taught in full
- **"How do attackers abuse OAuth in SaaS apps?"** — describe behaviour, it finds the technique
- **"What does MFA actually buy me?"** — a control, its coverage and its limits
- **"Quiz me on identity attacks"** — scenario questions, not definitions
- **"Threat model this service: ..."** — a project mapped to techniques, controls and logging

## What is here

```
.claude/
├─ skills/
│  ├─ attack-tutor/              learning — the main skill
│  │  └─ references/             mental model, architect playbook, stack map
│  └─ attack-threat-model/       applying ATT&CK to a real project
├─ agents/attack-researcher.md   subagent for multi-technique sweeps
└─ scripts/attack.py             query layer over the STIX data

attack-learning/progress.md      your learning record
```

`attack.py` is an implementation detail the skills call — it exists so a 51 MB STIX bundle never
enters the conversation. You can run it directly if you want (`--help` lists the commands), but
you should not need to.

## How the data is found

In order: `$ATTACK_STIX_DATA`, then a search upward from the working directory for
`enterprise-attack/enterprise-attack.json`, then `~/.cache/attack-stix/`, then a download from
the MITRE repository.

So inside this repo it reads the local bundle, and in any other project it fetches and caches
automatically. Nothing to configure.

## Using it in your application projects

Copy the toolkit into your personal skills directory once, and it works in every project:

```bash
mkdir -p ~/.claude/skills ~/.claude/agents ~/.claude/scripts
cp -r .claude/skills/attack-tutor .claude/skills/attack-threat-model ~/.claude/skills/
cp .claude/agents/attack-researcher.md ~/.claude/agents/
cp .claude/scripts/attack.py ~/.claude/scripts/
```

If you install this way, set `ATTACK_STIX_DATA` to this repo, or let the script fetch its own
copy — either works.

Per-project instead of globally: copy `.claude/` into that project.

## Scope

Default platform scope is cloud (IaaS/SaaS/Office Suite), Identity Provider, Containers, and
Linux/Windows/macOS servers — 581 of 697 Enterprise techniques. Change it by asking, or with
`--platforms` on the script.

**Cloud examples use Azure** — Entra ID, subscriptions, managed identities, Azure RBAC, Key
Vault, App Service, AKS, Microsoft 365. ATT&CK's own analytics are AWS-weighted
(`AWS:CloudTrail` appears 142 times against 9 for `azure:activity`), so the skills translate to
Azure equivalents and tell you when they are translating rather than quoting ATT&CK directly.
The translation table lives in `.claude/skills/attack-tutor/references/stack-map.md`.

Data is ATT&CK Enterprise v19.1, the bundle in this repository. Mobile and ICS are present in
the repo but the skills do not cover them; ask if you need that.

## A caveat worth keeping in mind

ATT&CK describes what attackers have been *publicly reported* doing, mostly after they already
have a foothold. It is not a checklist, not risk-ranked, and not a substitute for threat
modelling your own design. It says little about application logic flaws — authorisation bypass,
business logic abuse, injection — which live upstream in OWASP and STRIDE territory.
`.claude/skills/attack-tutor/references/concepts.md` covers this properly.
