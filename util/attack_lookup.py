#!/usr/bin/env python3
"""Query the ATT&CK STIX bundles in this repository from the command line.

Intended for threat-intel workflows such as mapping an incident report to
ATT&CK: resolve technique IDs, search for techniques by keyword, profile
software and groups, check whether IDs cited by a report are still current,
and emit an ATT&CK Navigator layer.

Only the Python standard library is required. Run with -h for usage.
"""

import argparse
import json
import os
import re
import sys

DOMAINS = ("enterprise-attack", "mobile-attack", "ics-attack")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# STIX types that carry an ATT&CK ID we care about, keyed by the label used in output.
TYPE_LABELS = {
    "attack-pattern": "technique",
    "malware": "software",
    "tool": "software",
    "intrusion-set": "group",
    "campaign": "campaign",
    "course-of-action": "mitigation",
    "x-mitre-data-component": "data component",
    "x-mitre-detection-strategy": "detection strategy",
    "x-mitre-analytic": "analytic",
    "x-mitre-tactic": "tactic",
}


def bundle_path(domain, version=None):
    name = domain if version is None else f"{domain}-{version}"
    return os.path.join(REPO_ROOT, domain, f"{name}.json")


class Bundle:
    """An ATT&CK STIX collection with lookup indexes built over it."""

    def __init__(self, domain, version=None):
        path = bundle_path(domain, version)
        if not os.path.exists(path):
            sys.exit(f"error: no such bundle: {path}")
        self.domain = domain
        self.path = path
        with open(path, encoding="utf-8") as handle:
            self.objects = json.load(handle)["objects"]

        self.by_stix_id = {obj["id"]: obj for obj in self.objects}
        self.by_attack_id = {}
        self.relationships = []
        for obj in self.objects:
            if obj["type"] == "relationship":
                self.relationships.append(obj)
                continue
            attack_id = attack_id_of(obj)
            if attack_id:
                self.by_attack_id[attack_id.upper()] = obj

        self._rels_from = {}
        self._rels_to = {}
        for rel in self.relationships:
            self._rels_from.setdefault(rel["source_ref"], []).append(rel)
            self._rels_to.setdefault(rel["target_ref"], []).append(rel)

    def get(self, attack_id):
        return self.by_attack_id.get(attack_id.upper())

    def resolve_name(self, name, types):
        """Find an object by exact ATT&CK ID, exact name, alias, then substring."""
        direct = self.get(name)
        if direct and direct["type"] in types:
            return direct
        needle = name.lower()
        candidates = [o for o in self.objects if o["type"] in types]
        for obj in candidates:
            names = [obj.get("name", "")] + obj.get("aliases", []) + obj.get("x_mitre_aliases", [])
            if any(n.lower() == needle for n in names):
                return obj
        partial = [o for o in candidates if needle in o.get("name", "").lower()]
        if len(partial) == 1:
            return partial[0]
        if partial:
            names = ", ".join(sorted(o["name"] for o in partial)[:12])
            sys.exit(f"error: '{name}' is ambiguous, matches: {names}")
        return None

    def rels_from(self, stix_id, relationship_type=None):
        rels = self._rels_from.get(stix_id, [])
        if relationship_type:
            rels = [r for r in rels if r["relationship_type"] == relationship_type]
        return rels

    def rels_to(self, stix_id, relationship_type=None):
        rels = self._rels_to.get(stix_id, [])
        if relationship_type:
            rels = [r for r in rels if r["relationship_type"] == relationship_type]
        return rels


def attack_id_of(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def url_of(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


def tactics_of(obj):
    return [phase["phase_name"] for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name", "").startswith("mitre")]


def status_of(obj):
    flags = []
    if obj.get("revoked"):
        flags.append("REVOKED")
    if obj.get("x_mitre_deprecated"):
        flags.append("DEPRECATED")
    return flags


def strip_citations(text):
    """Remove ATT&CK citation markers and markdown links so output stays readable."""
    text = re.sub(r"\(Citation:[^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)\]\(https?://[^)]+\)", r"\1", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def shorten(text, limit):
    text = strip_citations(text)
    if limit and len(text) > limit:
        return text[:limit].rsplit(" ", 1)[0] + " ..."
    return text


def label(obj):
    return TYPE_LABELS.get(obj["type"], obj["type"])


def describe(obj, bundle, full=False):
    """Render a single object as a text block."""
    lines = []
    attack_id = attack_id_of(obj) or "(no ID)"
    flags = status_of(obj)
    header = f"{attack_id}  {obj.get('name', '')}  [{label(obj)}]"
    if flags:
        header += "  ** " + " / ".join(flags) + " **"
    lines.append(header)
    if url_of(obj):
        lines.append(f"  url: {url_of(obj)}")
    tactics = tactics_of(obj)
    if tactics:
        lines.append(f"  tactics: {', '.join(tactics)}")
    platforms = obj.get("x_mitre_platforms")
    if platforms:
        lines.append(f"  platforms: {', '.join(platforms)}")
    aliases = obj.get("aliases") or obj.get("x_mitre_aliases")
    if aliases and len(aliases) > 1:
        lines.append(f"  aliases: {', '.join(aliases)}")
    for rel in bundle.rels_from(obj["id"], "revoked-by"):
        replacement = bundle.by_stix_id.get(rel["target_ref"])
        if replacement:
            lines.append(f"  revoked by: {attack_id_of(replacement)} {replacement.get('name')}")
    if obj.get("description"):
        lines.append("  " + shorten(obj["description"], None if full else 600).replace("\n", "\n  "))
    return "\n".join(lines)


def sub_and_parent(bundle, obj):
    """Return sub-technique children of a technique, if any."""
    attack_id = attack_id_of(obj) or ""
    return sorted(
        (o for o in bundle.objects
         if o["type"] == "attack-pattern"
         and (attack_id_of(o) or "").startswith(attack_id + ".")),
        key=lambda o: attack_id_of(o) or "",
    )


def print_users(bundle, technique):
    """Print the groups, campaigns and software ATT&CK records as using a technique."""
    users = {"group": [], "software": [], "campaign": []}
    for rel in bundle.rels_to(technique["id"], "uses"):
        source = bundle.by_stix_id.get(rel["source_ref"])
        if not source:
            continue
        kind = label(source)
        if kind in users:
            users[kind].append(f"{attack_id_of(source)} {source.get('name')}")
    for kind in ("group", "campaign", "software"):
        if users[kind]:
            names = sorted(set(users[kind]))
            print(f"  used by {kind}s ({len(names)}): {', '.join(names[:25])}"
                  + (" ..." if len(names) > 25 else ""))


def cmd_technique(args, bundle):
    for raw_id in args.ids:
        obj = bundle.get(raw_id)
        if not obj:
            print(f"{raw_id}: NOT FOUND in {bundle.domain}\n")
            continue
        print(describe(obj, bundle, full=args.full))
        subs = sub_and_parent(bundle, obj)
        if subs:
            print(f"  sub-techniques: {', '.join(attack_id_of(s) + ' ' + s['name'] for s in subs)}")
        if args.relationships:
            print_users(bundle, obj)
        if args.mitigations:
            print_mitigations(bundle, obj)
        if args.detections:
            print_detections(bundle, obj)
        print()


def print_mitigations(bundle, technique):
    rels = bundle.rels_to(technique["id"], "mitigates")
    if not rels:
        print("  mitigations: none listed")
        return
    print("  mitigations:")
    for rel in rels:
        mitigation = bundle.by_stix_id.get(rel["source_ref"])
        if mitigation and not mitigation.get("x_mitre_deprecated"):
            print(f"    {attack_id_of(mitigation)} {mitigation['name']}")


def print_detections(bundle, technique):
    """Print detection strategies, their analytics, and the log sources they need."""
    rels = bundle.rels_to(technique["id"], "detects")
    strategies = [bundle.by_stix_id[r["source_ref"]] for r in rels
                  if r["source_ref"] in bundle.by_stix_id]
    strategies = [s for s in strategies if s["type"] == "x-mitre-detection-strategy"]
    legacy = technique.get("x_mitre_detection")
    if not strategies and legacy:
        print("  detection (legacy field): " + shorten(legacy, 800))
        return
    if not strategies:
        print("  detections: none listed")
        return
    print("  detection strategies:")
    for strategy in strategies:
        print(f"    {attack_id_of(strategy)} {strategy['name']}")
        for analytic_ref in strategy.get("x_mitre_analytic_refs", []):
            analytic = bundle.by_stix_id.get(analytic_ref)
            if not analytic:
                continue
            sources = ", ".join(
                f"{s.get('name')}({s.get('channel')})"
                for s in analytic.get("x_mitre_log_source_references", [])
            )
            platforms = ",".join(analytic.get("x_mitre_platforms", []))
            print(f"      {attack_id_of(analytic)} [{platforms}] {shorten(analytic.get('description',''), 300)}")
            if sources:
                print(f"        log sources: {sources}")


def cmd_search(args, bundle):
    terms = [t.lower() for t in args.terms]
    types = {
        "technique": ["attack-pattern"],
        "software": ["malware", "tool"],
        "group": ["intrusion-set"],
        "campaign": ["campaign"],
        "mitigation": ["course-of-action"],
        "all": list(TYPE_LABELS),
    }[args.type]

    scored = []
    for obj in bundle.objects:
        if obj["type"] not in types:
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            if not args.include_deprecated:
                continue
        name = obj.get("name", "").lower()
        description = obj.get("description", "").lower()
        aliases = " ".join(obj.get("aliases", []) + obj.get("x_mitre_aliases", [])).lower()
        haystack = f"{name} {aliases} {description}"
        if not all(term in haystack for term in terms):
            continue
        # Name hits are far more relevant than description hits.
        score = sum(3 if term in name else 1 for term in terms)
        scored.append((score, attack_id_of(obj) or "", obj))

    scored.sort(key=lambda row: (-row[0], row[1]))
    if not scored:
        print(f"no matches for {' '.join(terms)} in {bundle.domain}")
        return
    for _, _, obj in scored[: args.limit]:
        print(describe(obj, bundle, full=False) if args.verbose else summary_line(obj))
    if len(scored) > args.limit:
        print(f"... {len(scored) - args.limit} more (raise --limit)")


def summary_line(obj):
    attack_id = attack_id_of(obj) or "-"
    tactics = ",".join(tactics_of(obj))
    flags = " ".join(f"[{f}]" for f in status_of(obj))
    parts = [f"{attack_id:<12}", f"{obj.get('name', ''):<45}", f"({label(obj)}"]
    parts.append(f"; {tactics})" if tactics else ")")
    return " ".join(parts) + (" " + flags if flags else "")


def cmd_software(args, bundle):
    obj = bundle.resolve_name(args.name, {"malware", "tool"})
    if not obj:
        print(f"'{args.name}' not found as software in {bundle.domain}. "
              f"Try: attack_lookup.py search --type software {args.name}")
        return
    print(describe(obj, bundle, full=args.full))
    techniques = []
    for rel in bundle.rels_from(obj["id"], "uses"):
        target = bundle.by_stix_id.get(rel["target_ref"])
        if target and target["type"] == "attack-pattern":
            techniques.append((attack_id_of(target), target["name"], rel.get("description", "")))
    print(f"\n  techniques ({len(techniques)}):")
    for attack_id, name, note in sorted(techniques):
        print(f"    {attack_id:<12} {name}")
        if args.verbose and note:
            print(f"        {shorten(note, 240)}")
    groups = sorted({
        f"{attack_id_of(bundle.by_stix_id[r['source_ref']])} "
        f"{bundle.by_stix_id[r['source_ref']]['name']}"
        for r in bundle.rels_to(obj["id"], "uses")
        if r["source_ref"] in bundle.by_stix_id
        and bundle.by_stix_id[r["source_ref"]]["type"] in ("intrusion-set", "campaign")
    })
    if groups:
        print(f"\n  used by ({len(groups)}): {', '.join(groups)}")


def cmd_group(args, bundle):
    obj = bundle.resolve_name(args.name, {"intrusion-set", "campaign"})
    if not obj:
        print(f"'{args.name}' not found as a group or campaign in {bundle.domain}. "
              f"Try: attack_lookup.py search --type all {args.name}")
        return
    print(describe(obj, bundle, full=args.full))
    techniques, software = [], []
    for rel in bundle.rels_from(obj["id"], "uses"):
        target = bundle.by_stix_id.get(rel["target_ref"])
        if not target:
            continue
        if target["type"] == "attack-pattern":
            techniques.append((attack_id_of(target), target["name"]))
        elif target["type"] in ("malware", "tool"):
            software.append(f"{attack_id_of(target)} {target['name']}")
    print(f"\n  techniques ({len(techniques)}):")
    for attack_id, name in sorted(set(techniques)):
        print(f"    {attack_id:<12} {name}")
    if software:
        print(f"\n  software ({len(set(software))}): {', '.join(sorted(set(software)))}")


def cmd_validate(args, bundle):
    """Check IDs cited by a report: unknown, deprecated, revoked, or current."""
    ids = args.ids or read_ids_from_stdin()
    for raw_id in ids:
        obj = bundle.get(raw_id)
        if not obj:
            print(f"{raw_id:<12} UNKNOWN     not present in {bundle.domain}")
            continue
        flags = status_of(obj)
        replacement = ""
        for rel in bundle.rels_from(obj["id"], "revoked-by"):
            target = bundle.by_stix_id.get(rel["target_ref"])
            if target:
                replacement = f" -> use {attack_id_of(target)} {target['name']}"
        state = "/".join(flags) if flags else "OK"
        print(f"{raw_id:<12} {state:<11} {obj.get('name', '')}{replacement}")


def read_ids_from_stdin():
    text = sys.stdin.read()
    return sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text)))


def cmd_extract(args, bundle):
    """Pull ATT&CK IDs out of a text file (a pasted report) and resolve them."""
    with open(args.file, encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    found = sorted(set(re.findall(r"\b(?:T\d{4}(?:\.\d{3})?|S\d{4}|G\d{4}|C\d{4}|M\d{4})\b", text)))
    if not found:
        print("no ATT&CK IDs found in file")
        return
    for attack_id in found:
        obj = bundle.get(attack_id)
        if not obj:
            print(f"{attack_id:<12} UNKNOWN (may belong to another domain)")
        else:
            print(summary_line(obj))


def cmd_layer(args, bundle):
    """Emit an ATT&CK Navigator layer for a set of technique IDs."""
    ids = args.ids or read_ids_from_stdin()
    techniques = []
    missing = []
    for attack_id in ids:
        obj = bundle.get(attack_id)
        if not obj or obj["type"] != "attack-pattern":
            missing.append(attack_id)
            continue
        entry = {
            "techniqueID": attack_id.upper(),
            "color": args.color,
            "comment": "",
            "enabled": True,
            "showSubtechniques": True,
        }
        tactics = tactics_of(obj)
        if tactics:
            # Navigator scores a technique per tactic; emit one entry per tactic.
            for tactic in tactics:
                item = dict(entry)
                item["tactic"] = tactic
                techniques.append(item)
        else:
            techniques.append(entry)

    layer = {
        "name": args.name,
        "versions": {"attack": "19", "navigator": "5.1.0", "layer": "4.5"},
        "domain": bundle.domain,
        "description": args.description,
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 1},
        "legendItems": [{"label": args.name, "color": args.color}],
        "showTacticRowBackground": True,
        "sorting": 0,
    }
    output = json.dumps(layer, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(output + "\n")
        print(f"wrote {args.out} ({len(techniques)} entries)")
    else:
        print(output)
    if missing:
        print(f"warning: skipped unresolved IDs: {', '.join(missing)}", file=sys.stderr)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Query the ATT&CK STIX bundles in this repository.",
        epilog="Examples:\n"
               "  attack_lookup.py technique T1566.002 --relationships --detections\n"
               "  attack_lookup.py search ntds credential\n"
               "  attack_lookup.py software Bumblebee\n"
               "  attack_lookup.py group Akira\n"
               "  attack_lookup.py validate T1086 T1059.001\n"
               "  attack_lookup.py extract report.md\n"
               "  attack_lookup.py layer T1189 T1204.002 --out layer.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--domain", default="enterprise-attack", choices=DOMAINS,
                        help="ATT&CK domain bundle to query (default: enterprise-attack)")
    parser.add_argument("--attack-version", dest="version", default=None,
                        help="pin a release, e.g. 17.1 (default: latest bundle in the folder)")
    sub = parser.add_subparsers(dest="command", required=True)

    technique = sub.add_parser("technique", help="show one or more techniques by ID")
    technique.add_argument("ids", nargs="+")
    technique.add_argument("--full", action="store_true", help="print untruncated descriptions")
    technique.add_argument("--relationships", "-r", action="store_true",
                           help="list groups, campaigns and software that use the technique")
    technique.add_argument("--mitigations", "-m", action="store_true")
    technique.add_argument("--detections", "-d", action="store_true",
                           help="list detection strategies, analytics and log sources")
    technique.set_defaults(func=cmd_technique)

    search = sub.add_parser("search", help="keyword search over names, aliases and descriptions")
    search.add_argument("terms", nargs="+")
    search.add_argument("--type", default="technique",
                        choices=["technique", "software", "group", "campaign", "mitigation", "all"])
    search.add_argument("--limit", type=int, default=25)
    search.add_argument("--verbose", "-v", action="store_true", help="include descriptions")
    search.add_argument("--include-deprecated", action="store_true")
    search.set_defaults(func=cmd_search)

    software = sub.add_parser("software", help="profile a malware or tool entry and its techniques")
    software.add_argument("name")
    software.add_argument("--full", action="store_true")
    software.add_argument("--verbose", "-v", action="store_true",
                          help="include the procedure text for each technique")
    software.set_defaults(func=cmd_software)

    group = sub.add_parser("group", help="profile a group or campaign and its techniques")
    group.add_argument("name")
    group.add_argument("--full", action="store_true")
    group.set_defaults(func=cmd_group)

    validate = sub.add_parser("validate",
                              help="check IDs for deprecation/revocation (reads stdin if no IDs)")
    validate.add_argument("ids", nargs="*")
    validate.set_defaults(func=cmd_validate)

    extract = sub.add_parser("extract", help="find and resolve ATT&CK IDs in a text file")
    extract.add_argument("file")
    extract.set_defaults(func=cmd_extract)

    layer = sub.add_parser("layer",
                           help="emit an ATT&CK Navigator layer (reads IDs from stdin if none given)")
    layer.add_argument("ids", nargs="*")
    layer.add_argument("--name", default="Incident mapping")
    layer.add_argument("--description", default="Generated by util/attack_lookup.py")
    layer.add_argument("--color", default="#e60d0d")
    layer.add_argument("--out")
    layer.set_defaults(func=cmd_layer)

    return parser


def main():
    args = build_parser().parse_args()
    bundle = Bundle(args.domain, args.version)
    args.func(args, bundle)


if __name__ == "__main__":
    main()
