#!/usr/bin/env python3
"""Query layer over the MITRE ATT&CK Enterprise STIX bundle.

This is called by the attack-tutor and attack-threat-model skills. It is not
meant to be driven by hand: it returns compact, pre-digested results so the
skill can teach from them without loading a 51 MB JSON file into context.

Data resolution order: $ATTACK_STIX_DATA, then a repo walk up from cwd, then
the local cache, then a download from the MITRE repository.
"""

import argparse
import json
import os
import re
import sys
import textwrap
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

BUNDLE = "enterprise-attack/enterprise-attack.json"
CACHE = Path.home() / ".cache" / "attack-stix" / "enterprise-attack.json"
REMOTE = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

# Default teaching scope: cloud, identity, containers and general-purpose servers.
DEFAULT_PLATFORMS = [
    "IaaS",
    "SaaS",
    "Office Suite",
    "Identity Provider",
    "Containers",
    "Linux",
    "Windows",
    "macOS",
]


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------


def locate() -> Path:
    """Find a bundle locally, or download one into the cache."""
    env = os.environ.get("ATTACK_STIX_DATA")
    if env:
        for cand in (Path(env), Path(env) / BUNDLE):
            if cand.is_file():
                return cand

    here = Path.cwd().resolve()
    for parent in [here, *here.parents]:
        cand = parent / BUNDLE
        if cand.is_file():
            return cand

    if CACHE.is_file():
        return CACHE

    CACHE.parent.mkdir(parents=True, exist_ok=True)
    print(f"[attack.py] downloading ATT&CK data to {CACHE} ...", file=sys.stderr)
    with urllib.request.urlopen(REMOTE, timeout=180) as resp:
        CACHE.write_bytes(resp.read())
    return CACHE


class Attack:
    def __init__(self, path: Path):
        self.path = path
        objs = json.loads(path.read_text())["objects"]
        self.by_id = {o["id"]: o for o in objs}

        self.techniques, self.mitigations, self.tactics = [], [], []
        self.groups, self.strategies, self.analytics, self.components = [], [], [], {}
        rels = []
        for o in objs:
            t = o["type"]
            if t == "x-mitre-data-component":
                self.components[o["id"]] = o
            if t == "relationship":
                rels.append(o)
                continue
            if not live(o):
                continue
            if t == "attack-pattern":
                self.techniques.append(o)
            elif t == "course-of-action":
                self.mitigations.append(o)
            elif t == "x-mitre-tactic":
                self.tactics.append(o)
            elif t in ("intrusion-set", "campaign"):
                self.groups.append(o)
            elif t == "x-mitre-detection-strategy":
                self.strategies.append(o)
            elif t == "x-mitre-analytic":
                self.analytics.append(o)

        # Relationship indexes, deprecated/revoked objects excluded throughout.
        self.mitigated_by = defaultdict(list)  # technique id -> [mitigation]
        self.mitigates = defaultdict(list)  # mitigation id -> [technique]
        self.used_by = defaultdict(list)  # technique id -> [group/campaign]
        self.detected_by = defaultdict(list)  # technique id -> [detection strategy]
        self.subs_of = defaultdict(list)  # parent id -> [sub-technique]
        self.parent_of = {}  # sub id -> parent

        for r in rels:
            if not live(r):
                continue
            src, dst = self.by_id.get(r["source_ref"]), self.by_id.get(r["target_ref"])
            if not src or not dst or not live(src) or not live(dst):
                continue
            kind = r.get("relationship_type")
            if kind == "mitigates" and dst["type"] == "attack-pattern":
                self.mitigated_by[dst["id"]].append(src)
                self.mitigates[src["id"]].append(dst)
            elif kind == "uses" and dst["type"] == "attack-pattern":
                if src["type"] in ("intrusion-set", "campaign"):
                    self.used_by[dst["id"]].append(src)
            elif kind == "detects" and dst["type"] == "attack-pattern":
                self.detected_by[dst["id"]].append(src)
            elif kind == "subtechnique-of":
                self.subs_of[dst["id"]].append(src)
                self.parent_of[src["id"]] = dst

        self.by_eid = {}
        for o in self.techniques + self.mitigations + self.tactics + self.groups:
            e = eid(o)
            if e:
                self.by_eid[e.upper()] = o

    # -- lookups ---------------------------------------------------------

    def technique(self, ident: str):
        o = self.by_eid.get(ident.upper())
        if o and o["type"] == "attack-pattern":
            return o
        matches = [t for t in self.techniques if t["name"].lower() == ident.lower()]
        return matches[0] if matches else None

    def usage(self, tech) -> int:
        """How many distinct named groups/campaigns are recorded using this."""
        return len({g["id"] for g in self.used_by.get(tech["id"], [])})

    def in_scope(self, platforms):
        want = set(platforms)
        return [t for t in self.techniques if want & set(t.get("x_mitre_platforms", []))]

    def log_sources(self, tech):
        """Concrete log sources an analytic would read for this technique."""
        names = Counter()
        for strat in self.detected_by.get(tech["id"], []):
            for ref in strat.get("x_mitre_analytic_refs", []):
                an = self.by_id.get(ref)
                if not an:
                    continue
                for ls in an.get("x_mitre_log_source_references", []):
                    if ls.get("name"):
                        names[ls["name"]] += 1
        return names


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def live(o) -> bool:
    return not o.get("revoked") and not o.get("x_mitre_deprecated")


def eid(o):
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id")
    return None


def url(o):
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("url", "")
    return ""


def tactics_of(o):
    return [p["phase_name"] for p in o.get("kill_chain_phases", [])]


def clean(text: str, limit: int = 700) -> str:
    """Strip STIX citation markers and markdown links down to readable prose."""
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[ \t]+", " ", text).strip()
    if len(text) > limit:
        cut = text[:limit]
        text = cut[: cut.rfind(". ") + 1] if ". " in cut else cut + "..."
    return text


def wrap(text, indent=""):
    return textwrap.fill(text, 96, initial_indent=indent, subsequent_indent=indent)


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def cmd_technique(a: Attack, args):
    t = a.technique(args.id)
    if not t:
        sys.exit(f"No technique matching {args.id!r}. Try: attack.py search {args.id}")

    print(f"{eid(t)}  {t['name']}")
    print(f"URL        {url(t)}")
    print(f"Tactics    {', '.join(tactics_of(t)) or '-'}")
    print(f"Platforms  {', '.join(t.get('x_mitre_platforms', [])) or '-'}")
    if t.get("x_mitre_permissions_required"):
        print(f"Needs      {', '.join(t['x_mitre_permissions_required'])}")

    parent = a.parent_of.get(t["id"])
    if parent:
        print(f"Parent     {eid(parent)} {parent['name']}")

    print(f"Used by    {a.usage(t)} named groups/campaigns")
    print(f"\nDESCRIPTION\n{wrap(clean(t['description'], 900))}")

    subs = sorted(a.subs_of.get(t["id"], []), key=lambda s: -a.usage(s))
    if subs:
        print(f"\nSUB-TECHNIQUES ({len(subs)}, most-used first)")
        for s in subs[: args.limit]:
            print(f"  {eid(s):10} {s['name'][:48]:48} used by {a.usage(s)}")

    mits = sorted(a.mitigated_by.get(t["id"], []), key=lambda m: eid(m) or "")
    print(f"\nMITIGATIONS ({len(mits)})")
    for m in mits or []:
        print(f"  {eid(m):7} {m['name']}")
    if not mits:
        print("  none — ATT&CK treats this as something to detect, not prevent")

    logs = a.log_sources(t)
    if logs:
        print(f"\nLOG SOURCES (from ATT&CK detection analytics)")
        for name, n in logs.most_common(args.limit):
            print(f"  {name:36} referenced by {n} analytic(s)")

    actors = sorted({g["name"] for g in a.used_by.get(t["id"], [])})
    if actors:
        print(f"\nOBSERVED IN USE BY\n{wrap(', '.join(actors[:24]), '  ')}")


def cmd_search(a: Attack, args):
    q = args.text.lower()
    hits = []
    for t in a.techniques:
        score = 0
        if q in t["name"].lower():
            score += 10
        if q in clean(t.get("description", ""), 4000).lower():
            score += 3
        if score:
            hits.append((score + min(a.usage(t), 9) / 10, t))
    hits.sort(key=lambda x: -x[0])
    if not hits:
        sys.exit(f"Nothing matched {args.text!r}.")
    print(f"{len(hits)} technique(s) matched {args.text!r}; top {min(args.limit, len(hits))}:\n")
    for _, t in hits[: args.limit]:
        print(f"  {eid(t):10} {t['name'][:44]:44} [{','.join(tactics_of(t))[:34]}] used by {a.usage(t)}")


def cmd_path(a: Attack, args):
    """The curriculum: in-scope techniques ordered by real-world adversary usage."""
    scoped = a.in_scope(args.platforms)
    ranked = sorted(scoped, key=lambda t: (-a.usage(t), eid(t) or ""))
    ranked = [t for t in ranked if a.usage(t) > 0]
    print(f"Learning path — {len(scoped)} techniques in scope for {', '.join(args.platforms)}")
    print(f"Ordered by how many real groups/campaigns use them. Showing {args.top}.\n")
    for i, t in enumerate(ranked[: args.top], 1):
        star = "*" if not a.parent_of.get(t["id"]) else " "
        print(
            f"{i:3}.{star} {eid(t):10} {t['name'][:42]:42} "
            f"[{','.join(tactics_of(t))[:30]:30}] {a.usage(t):3} groups"
        )
    print("\n* = top-level technique (the rest are sub-techniques)")


def cmd_tactic(a: Attack, args):
    name = args.name.lower().replace(" ", "-")
    tac = next(
        (
            t
            for t in a.tactics
            if t.get("x_mitre_shortname") == name or (eid(t) or "").upper() == args.name.upper()
        ),
        None,
    )
    if not tac:
        print("Known tactics:")
        for t in sorted(a.tactics, key=lambda x: eid(x) or ""):
            print(f"  {eid(t):7} {t['name']:24} {t['x_mitre_shortname']}")
        sys.exit(1)

    print(f"{eid(tac)}  {tac['name']}  (goal: {tac['x_mitre_shortname']})")
    print(f"\n{wrap(clean(tac['description'], 600))}\n")
    scoped = [
        t
        for t in a.in_scope(args.platforms)
        if tac["x_mitre_shortname"] in tactics_of(t) and not a.parent_of.get(t["id"])
    ]
    scoped.sort(key=lambda t: -a.usage(t))
    print(f"TOP-LEVEL TECHNIQUES IN SCOPE ({len(scoped)}), most-used first:")
    for t in scoped[: args.limit]:
        subs = len(a.subs_of.get(t["id"], []))
        extra = f"{subs} subs" if subs else ""
        print(f"  {eid(t):8} {t['name'][:44]:44} {a.usage(t):3} groups  {extra}")


def cmd_mitigation(a: Attack, args):
    m = a.by_eid.get(args.id.upper())
    if not m or m["type"] != "course-of-action":
        matches = [x for x in a.mitigations if args.id.lower() in x["name"].lower()]
        if not matches:
            print("Mitigations, by how many techniques they address:")
            ranked = sorted(a.mitigations, key=lambda x: -len(a.mitigates[x["id"]]))
            for x in ranked[:25]:
                print(f"  {eid(x):7} {x['name'][:44]:44} {len(a.mitigates[x['id']]):3} techniques")
            sys.exit(1)
        m = matches[0]

    covered = a.mitigates[m["id"]]
    scoped = [t for t in covered if set(args.platforms) & set(t.get("x_mitre_platforms", []))]
    print(f"{eid(m)}  {m['name']}")
    print(f"URL        {url(m)}")
    print(f"Addresses  {len(covered)} techniques total, {len(scoped)} in your scope")
    print(f"\n{wrap(clean(m['description'], 1100))}\n")
    scoped.sort(key=lambda t: -a.usage(t))
    print(f"TECHNIQUES IT ADDRESSES IN SCOPE (top {min(args.limit, len(scoped))} by usage):")
    for t in scoped[: args.limit]:
        print(f"  {eid(t):10} {t['name'][:44]:44} {a.usage(t):3} groups")


def cmd_actors(a: Attack, args):
    t = a.technique(args.id)
    if not t:
        sys.exit(f"No technique matching {args.id!r}")
    users = {g["id"]: g for g in a.used_by.get(t["id"], [])}.values()
    print(f"{eid(t)} {t['name']} — used by {len(users)} groups/campaigns\n")
    for g in sorted(users, key=lambda x: x["name"]):
        kind = "campaign" if g["type"] == "campaign" else "group"
        print(f"  {eid(g) or '-':8} {g['name'][:34]:34} ({kind})")


def cmd_logs(a: Attack, args):
    t = a.technique(args.id)
    if not t:
        sys.exit(f"No technique matching {args.id!r}")
    strategies = a.detected_by.get(t["id"], [])
    print(f"{eid(t)} {t['name']} — {len(strategies)} detection strategy/strategies\n")
    if not strategies:
        print("ATT&CK publishes no detection strategy for this technique.")
        return
    for s in strategies:
        print(f"{eid(s)}  {s['name']}")
        for ref in s.get("x_mitre_analytic_refs", []):
            an = a.by_id.get(ref)
            if not an:
                continue
            plats = ", ".join(an.get("x_mitre_platforms", []))
            print(f"  {eid(an)} [{plats}]")
            print(wrap(clean(an.get("description", ""), 420), "    "))
            for ls in an.get("x_mitre_log_source_references", []):
                print(f"      log: {ls.get('name','?')}  ({ls.get('channel','')})")
        print()


def cmd_scope(a: Attack, args):
    scoped = a.in_scope(args.platforms)
    parents = [t for t in scoped if not a.parent_of.get(t["id"])]
    print(f"Platforms   {', '.join(args.platforms)}")
    print(f"In scope    {len(scoped)} techniques ({len(parents)} top-level, "
          f"{len(scoped)-len(parents)} sub-techniques) of {len(a.techniques)} total\n")

    by_tactic = Counter()
    for t in scoped:
        for ph in tactics_of(t):
            by_tactic[ph] += 1
    print("BY TACTIC (adversary goal)")
    order = {t["x_mitre_shortname"]: eid(t) for t in a.tactics}
    for ph, n in sorted(by_tactic.items(), key=lambda x: order.get(x[0], "")):
        print(f"  {order.get(ph,'-'):7} {ph:24} {n:4} techniques")

    print("\nHIGHEST-LEVERAGE MITIGATIONS IN THIS SCOPE")
    ranked = []
    for m in a.mitigations:
        n = len([t for t in a.mitigates[m["id"]] if set(args.platforms) & set(t.get("x_mitre_platforms", []))])
        if n:
            ranked.append((n, m))
    ranked.sort(key=lambda x: -x[0])
    for n, m in ranked[:12]:
        print(f"  {eid(m):7} {m['name'][:44]:44} {n:3} techniques")


def cmd_where(a: Attack, args):
    print(a.path)


# --------------------------------------------------------------------------


def main():
    # Shared options, accepted either before or after the subcommand.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--platforms", default=",".join(DEFAULT_PLATFORMS),
                        help="comma-separated ATT&CK platforms to scope to")
    common.add_argument("--limit", type=int, default=12, help="max rows in list sections")

    p = argparse.ArgumentParser(parents=[common], description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, help_):
        return sub.add_parser(name, parents=[common], help=help_)

    s = add("technique", "full teaching detail for one technique")
    s.add_argument("id")
    s.set_defaults(fn=cmd_technique)

    s = add("search", "find techniques by keyword")
    s.add_argument("text")
    s.set_defaults(fn=cmd_search)

    s = add("path", "learning curriculum ranked by real-world usage")
    s.add_argument("--top", type=int, default=25)
    s.set_defaults(fn=cmd_path)

    s = add("tactic", "techniques under one adversary goal")
    s.add_argument("name")
    s.set_defaults(fn=cmd_tactic)

    s = add("mitigation", "a control and what it covers")
    s.add_argument("id")
    s.set_defaults(fn=cmd_mitigation)

    s = add("actors", "who uses a technique")
    s.add_argument("id")
    s.set_defaults(fn=cmd_actors)

    s = add("logs", "detection strategies and log sources")
    s.add_argument("id")
    s.set_defaults(fn=cmd_logs)

    s = add("scope", "what your platform scope covers")
    s.set_defaults(fn=cmd_scope)

    s = add("where", "print the data file in use")
    s.set_defaults(fn=cmd_where)

    args = p.parse_args()
    args.platforms = [x.strip() for x in args.platforms.split(",") if x.strip()]
    args.fn(Attack(locate()), args)


if __name__ == "__main__":
    main()
