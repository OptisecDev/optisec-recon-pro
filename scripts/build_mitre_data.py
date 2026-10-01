"""Distill MITRE ATT&CK Enterprise into the two slim JSON files Attack
Navigator loads (data/mitre_attack_enterprise_slim.json,
data/mitre_attack_groups_slim.json), replacing the hardcoded
TACTICS/TECHNIQUES/APT_GROUPS literals that used to live in
modules/threat_intel/attack_navigator.py.

Why distilled instead of embedding the official file as-is: the official
enterprise-attack.json (github.com/mitre/cti) is a full STIX 2.1 bundle —
~46MB on disk, ~26k objects (relationships, mitigations, detection
strategies, data sources, etc. that Attack Navigator doesn't use), and
json.load()-ing it alone peaks at ~240MB RSS, which eats half of this
app's 512MB memory budget before the app itself has loaded anything. The
slim files below keep only what Attack Navigator renders (tactic/technique
id+name+kill-chain-phase+platform, group id/name/aliases/description +
its real technique and malware/tool associations from STIX "uses"
relationships) — a few hundred KB total, negligible to load.

This script is NOT run automatically at build or deploy time — the slim
files are committed to the repo and loaded as static data. Re-run it by
hand to refresh them when MITRE publishes a new ATT&CK release:

    python scripts/build_mitre_data.py
    python scripts/build_mitre_data.py --input /path/to/enterprise-attack.json

No "severity" or "risk_level" field is produced for techniques/groups —
MITRE ATT&CK doesn't score either; attack_navigator.py no longer invents
one (see commit introducing this script for the prior arbitrary values
this replaced).
"""
import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SOURCE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
SOURCE_REPO = "https://github.com/mitre/cti"

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_TECHNIQUES = REPO_ROOT / "data" / "mitre_attack_enterprise_slim.json"
OUT_GROUPS = REPO_ROOT / "data" / "mitre_attack_groups_slim.json"

_DESC_MAX = 500


def _external_id(stix_obj: dict) -> str | None:
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _external_url(stix_obj: dict) -> str | None:
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None


def _live(stix_obj: dict) -> bool:
    """Non-deprecated, non-revoked — matches what attack.mitre.org shows."""
    return not stix_obj.get("revoked") and not stix_obj.get("x_mitre_deprecated")


def fetch_bundle(path: str | None) -> dict:
    if path:
        with open(path, "rb") as f:
            return json.load(f)
    print(f"Fetching {SOURCE_URL} ...", file=sys.stderr)
    with urllib.request.urlopen(SOURCE_URL, timeout=60) as resp:
        return json.load(resp)


def build(bundle: dict) -> tuple[dict, dict]:
    objects = bundle["objects"]

    tactics = [o for o in objects if o["type"] == "x-mitre-tactic" and _live(o)]
    techniques = [o for o in objects if o["type"] == "attack-pattern" and _live(o)]
    groups = [o for o in objects if o["type"] == "intrusion-set" and _live(o)]
    malware_tools = {
        o["id"]: o.get("name")
        for o in objects
        if o["type"] in ("malware", "tool") and _live(o)
    }
    attack_pattern_by_stix_id = {o["id"]: o for o in techniques}

    uses_rels = [
        o for o in objects
        if o["type"] == "relationship" and o.get("relationship_type") == "uses"
    ]
    group_technique_ids: dict[str, set[str]] = {}
    group_malware_names: dict[str, set[str]] = {}
    for rel in uses_rels:
        src, tgt = rel.get("source_ref", ""), rel.get("target_ref", "")
        if not src.startswith("intrusion-set--"):
            continue
        if tgt.startswith("attack-pattern--"):
            ap = attack_pattern_by_stix_id.get(tgt)
            tid = _external_id(ap) if ap else None
            if tid:
                group_technique_ids.setdefault(src, set()).add(tid)
        elif tgt in malware_tools:
            group_malware_names.setdefault(src, set()).add(malware_tools[tgt])

    slim_tactics = []
    for t in sorted(tactics, key=lambda o: _external_id(o) or ""):
        slim_tactics.append({
            "id": _external_id(t),
            "name": t.get("name"),
            "shortname": t.get("x_mitre_shortname"),
        })

    slim_techniques = []
    for t in techniques:
        tid = _external_id(t)
        if not tid:
            continue
        phases = [
            kc.get("phase_name") for kc in t.get("kill_chain_phases", [])
            if kc.get("kill_chain_name") == "mitre-attack"
        ]
        slim_techniques.append({
            "id": tid,
            "name": t.get("name"),
            "tactics": phases,
            "platforms": t.get("x_mitre_platforms", []),
            "is_subtechnique": bool(t.get("x_mitre_is_subtechnique", False)),
            "description": (t.get("description") or "").strip()[:_DESC_MAX],
        })
    slim_techniques.sort(key=lambda t: t["id"])

    slim_groups = []
    for g in groups:
        gid = _external_id(g)
        if not gid:
            continue
        slim_groups.append({
            "id": gid,
            "name": g.get("name"),
            "aliases": g.get("aliases", []),
            "description": (g.get("description") or "").strip()[:_DESC_MAX],
            "url": _external_url(g),
            "techniques": sorted(group_technique_ids.get(g["id"], [])),
            "malware": sorted(group_malware_names.get(g["id"], [])),
        })
    slim_groups.sort(key=lambda g: g["id"])

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta = {
        "source": SOURCE_REPO,
        "source_file": "enterprise-attack/enterprise-attack.json",
        "fetched_at": now,
        "stix_spec_version": bundle.get("spec_version"),
    }

    techniques_doc = {
        "_meta": meta,
        "tactics": slim_tactics,
        "techniques": slim_techniques,
    }
    groups_doc = {
        "_meta": meta,
        "groups": slim_groups,
    }
    return techniques_doc, groups_doc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", help="Local enterprise-attack.json path (skip the network fetch)")
    args = parser.parse_args()

    bundle = fetch_bundle(args.input)
    techniques_doc, groups_doc = build(bundle)

    OUT_TECHNIQUES.parent.mkdir(parents=True, exist_ok=True)
    OUT_TECHNIQUES.write_text(json.dumps(techniques_doc, indent=None, separators=(",", ":")))
    OUT_GROUPS.write_text(json.dumps(groups_doc, indent=None, separators=(",", ":")))

    print(f"{OUT_TECHNIQUES}: {len(techniques_doc['tactics'])} tactics, "
          f"{len(techniques_doc['techniques'])} techniques "
          f"({OUT_TECHNIQUES.stat().st_size / 1024:.1f} KB)")
    print(f"{OUT_GROUPS}: {len(groups_doc['groups'])} groups "
          f"({OUT_GROUPS.stat().st_size / 1024:.1f} KB)")


if __name__ == "__main__":
    main()
