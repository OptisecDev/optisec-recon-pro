"""
MITRE ATT&CK Auto-Mapping

Deterministic (no AI/LLM involved) finding → ATT&CK technique/tactic
mapping, enriched with live technique names/descriptions/mitigations
pulled from MITRE's own STIX bundle
(https://github.com/mitre/cti — enterprise-attack.json) when reachable.

Design notes:
  - _MAPPING_RULES is a fixed lookup table (finding_type -> technique_ids +
    tactic_ids) reviewed by hand against the public ATT&CK matrix — never
    inferred by a model, so results are reproducible and auditable.
  - The full STIX bundle is ~30MB; rather than caching it verbatim we
    parse it once into a small {technique_id/tactic_id -> name/
    description/mitigations} index and cache *that* at /tmp/mitre_cache.json
    for 7 days.
  - If the bundle can't be fetched (offline, GitHub down) and no cache
    exists yet, map_finding_to_attack() still returns correct technique/
    tactic IDs and names from a small built-in static table (the same
    well-known ATT&CK names/IDs referenced by _MAPPING_RULES) — only the
    longer description/mitigations fields are left empty. The mapping
    itself never depends on network access.
"""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import aiohttp

logger = logging.getLogger("osint.mitre_mapping")

MITRE_ATTACK_BUNDLE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

_MITRE_CACHE_PATH = Path("/tmp/mitre_cache.json")
_MITRE_CACHE_TTL_SECONDS = 7 * 24 * 3600

_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=60)
_USER_AGENT = "OPTISEC-Recon-Pro-MitreMapping/1.0"

# Process-local memoization on top of the disk cache, so a single running
# process doesn't re-read/re-parse the cache file on every call.
_index_memo: dict | None = None


# ── Kill chain / tactic reference data ─────────────────────────────────────────
# The 14 MITRE Enterprise ATT&CK tactics, in official kill-chain order —
# IDs and names are stable and part of the public ATT&CK spec.
_KILL_CHAIN_ORDER: list[str] = [
    "TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
    "TA0006", "TA0007", "TA0008", "TA0009", "TA0011", "TA0010", "TA0040",
]

_TACTIC_NAMES: dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

# Static fallback names for every technique referenced by _MAPPING_RULES —
# used only when the live MITRE bundle/index is unavailable.
_TECHNIQUE_NAMES: dict[str, str] = {
    "T1021.004": "Remote Services: SSH",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1078": "Valid Accounts",
    "T1190": "Exploit Public-Facing Application",
    "T1040": "Network Sniffing",
    "T1557": "Adversary-in-the-Middle",
    "T1059.007": "Command and Scripting Interpreter: JavaScript",
    "T1185": "Browser Session Hijacking",
    "T1110": "Brute Force",
    "T1589.002": "Gather Victim Identity Information: Email Addresses",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1584.001": "Compromise Infrastructure: Domains",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1590.002": "Gather Victim Network Information: DNS",
    "T1530": "Data from Cloud Storage Object",
    "T1552": "Unsecured Credentials",
    "T1083": "File and Directory Discovery",
}


# ── Deterministic finding → ATT&CK mapping rules ───────────────────────────────

def _rule(techniques: list[str], tactics: list[str]) -> dict:
    return {"techniques": techniques, "tactics": tactics}


_MAPPING_RULES: dict[str, dict] = {
    "port_21_open": _rule(["T1021.004"], ["TA0008"]),
    "port_22_open": _rule(["T1021.004"], ["TA0008"]),
    "port_23_open": _rule(["T1021.004", "T1078"], ["TA0008"]),
    "port_3389_open": _rule(["T1021.001"], ["TA0008"]),
    "port_80_open": _rule(["T1190"], ["TA0001"]),
    "port_443_open": _rule(["T1190"], ["TA0001"]),
    "port_445_open": _rule(["T1021.002"], ["TA0008"]),
    "port_1433_open": _rule(["T1190"], ["TA0001"]),
    "port_3306_open": _rule(["T1190"], ["TA0001"]),
    "port_27017_open": _rule(["T1190"], ["TA0001"]),
    "weak_tls_10": _rule(["T1040"], ["TA0006"]),
    "weak_tls_11": _rule(["T1040"], ["TA0006"]),
    "missing_hsts": _rule(["T1557"], ["TA0006"]),
    "missing_csp": _rule(["T1059.007"], ["TA0002"]),
    "missing_xframe": _rule(["T1185"], ["TA0006"]),
    "missing_xcontent": _rule(["T1059.007"], ["TA0002"]),
    "credential_exposure": _rule(["T1078", "T1110"], ["TA0001"]),
    "email_breach": _rule(["T1589.002"], ["TA0043"]),
    "github_secret_exposed": _rule(["T1552.001"], ["TA0006"]),
    "subdomain_takeover": _rule(["T1584.001"], ["TA0042"]),
    "open_redirect": _rule(["T1566.002"], ["TA0001"]),
    "self_signed_cert": _rule(["T1557"], ["TA0006"]),
    "cert_expired": _rule(["T1557"], ["TA0006"]),
    "weak_cipher": _rule(["T1040"], ["TA0006"]),
    "dns_zone_transfer": _rule(["T1590.002"], ["TA0043"]),
    "s3_bucket_exposed": _rule(["T1530"], ["TA0009"]),
    "api_key_exposed": _rule(["T1552.001"], ["TA0006"]),
    "password_in_url": _rule(["T1552"], ["TA0006"]),
    "directory_listing": _rule(["T1083"], ["TA0007"]),
    "backup_file_exposed": _rule(["T1083"], ["TA0007"]),
}


def list_supported_finding_types() -> list[str]:
    return sorted(_MAPPING_RULES)


# ── MITRE ATT&CK bundle fetch + index build ────────────────────────────────────

def _external_id(stix_obj: dict) -> str | None:
    for ref in stix_obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def _build_index(bundle: dict) -> dict:
    """Reduce the ~30MB STIX bundle to a small {techniques, tactics} index
    keyed by ATT&CK ID, keeping only what map_finding_to_attack() needs."""
    objects = bundle.get("objects", []) or []

    tactics: dict[str, dict] = {}
    tactic_name_by_shortname: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            ext_id = _external_id(obj)
            shortname = obj.get("x_mitre_shortname")
            if ext_id and shortname:
                tactics[ext_id] = {"id": ext_id, "name": obj.get("name")}
                tactic_name_by_shortname[shortname] = ext_id

    coa_by_id = {obj["id"]: obj for obj in objects if obj.get("type") == "course-of-action"}
    technique_by_stix_id = {obj["id"]: obj for obj in objects if obj.get("type") == "attack-pattern"}

    mitigations_by_technique: dict[str, list[dict]] = defaultdict(list)
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "mitigates":
            continue
        coa = coa_by_id.get(obj.get("source_ref"))
        technique = technique_by_stix_id.get(obj.get("target_ref"))
        if not coa or not technique:
            continue
        ext_id = _external_id(technique)
        if ext_id:
            mitigations_by_technique[ext_id].append({
                "name": coa.get("name"),
                "description": (coa.get("description") or "")[:300],
            })

    techniques: dict[str, dict] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext_id = _external_id(obj)
        if not ext_id:
            continue
        phase_names = [
            p.get("phase_name") for p in obj.get("kill_chain_phases", []) or []
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        technique_tactics = [
            tactics[tactic_name_by_shortname[p]]
            for p in phase_names
            if p in tactic_name_by_shortname and tactic_name_by_shortname[p] in tactics
        ]
        techniques[ext_id] = {
            "id": ext_id,
            "name": obj.get("name"),
            "description": (obj.get("description") or "")[:500],
            "tactics": technique_tactics,
            "mitigations": mitigations_by_technique.get(ext_id, [])[:5],
        }

    return {"techniques": techniques, "tactics": tactics}


async def _fetch_attack_bundle() -> dict:
    async with aiohttp.ClientSession(timeout=_HTTP_TIMEOUT, headers={"User-Agent": _USER_AGENT}) as session:
        async with session.get(MITRE_ATTACK_BUNDLE_URL) as resp:
            resp.raise_for_status()
            return await resp.json(content_type=None)


def _load_index_cache() -> dict | None:
    try:
        raw = json.loads(_MITRE_CACHE_PATH.read_text())
    except (OSError, ValueError):
        return None
    if time.time() - raw.get("cached_at", 0) >= _MITRE_CACHE_TTL_SECONDS:
        return None
    return raw.get("index")


def _save_index_cache(index: dict) -> None:
    try:
        _MITRE_CACHE_PATH.write_text(json.dumps({"cached_at": time.time(), "index": index}))
    except OSError as exc:
        logger.warning("[mitre] could not write cache file %s: %s", _MITRE_CACHE_PATH, exc)


async def _get_attack_index(force_refresh: bool = False) -> dict:
    """
    Return the {techniques, tactics} lookup index, sourced from (in
    order): process memo -> /tmp/mitre_cache.json (if <7 days old) ->
    a fresh download of MITRE's STIX bundle. Falls back to an empty index
    (map_finding_to_attack() then uses its static name tables) if none of
    those succeed. Never raises.
    """
    global _index_memo
    if _index_memo is not None and not force_refresh:
        return _index_memo

    if not force_refresh:
        cached = _load_index_cache()
        if cached is not None:
            cached["_source"] = "cached_mitre_data"
            _index_memo = cached
            return cached

    try:
        bundle = await _fetch_attack_bundle()
        index = _build_index(bundle)
        index["_source"] = "live_mitre_data"
        _save_index_cache(index)
        _index_memo = index
        return index
    except (aiohttp.ClientError, ValueError, KeyError) as exc:
        logger.warning("[mitre] could not fetch/parse ATT&CK bundle, using static fallback names: %s", exc)
        fallback = {"techniques": {}, "tactics": {}, "_source": "static_fallback"}
        _index_memo = fallback
        return fallback


# ── Technique/tactic description lookup (live index + static fallback) ────────

def _describe_technique(technique_id: str, index: dict) -> dict:
    live = (index.get("techniques") or {}).get(technique_id)
    if live:
        return {
            "id": technique_id, "name": live.get("name"),
            "description": live.get("description"),
            "mitigations": live.get("mitigations") or [],
        }
    return {
        "id": technique_id,
        "name": _TECHNIQUE_NAMES.get(technique_id, technique_id),
        "description": None,
        "mitigations": [],
    }


def _describe_tactic(tactic_id: str, index: dict) -> dict:
    live = (index.get("tactics") or {}).get(tactic_id)
    if live:
        return {"id": tactic_id, "name": live.get("name")}
    return {"id": tactic_id, "name": _TACTIC_NAMES.get(tactic_id, tactic_id)}


# ── Public mapping API ──────────────────────────────────────────────────────────

async def map_finding_to_attack(finding_type: str, finding_value: Any = None) -> dict:
    """
    Deterministically map a recon `finding_type` (e.g. "port_22_open",
    "missing_hsts", "credential_exposure") to its MITRE ATT&CK
    technique(s) and tactic(s) via the fixed _MAPPING_RULES table — no AI
    involved.

    Returns {finding_type, finding_value, mapped, techniques, tactics,
    data_source}. `techniques`/`tactics` are lists of {id, name,
    description, mitigations} / {id, name}. `mapped` is False (with an
    `error` explaining why) when `finding_type` has no known rule. Never
    raises.
    """
    rule = _MAPPING_RULES.get(finding_type)
    if not rule:
        return {
            "finding_type": finding_type, "finding_value": finding_value,
            "mapped": False, "techniques": [], "tactics": [],
            "error": f"no ATT&CK mapping rule for finding_type={finding_type!r}",
        }

    index = await _get_attack_index()
    return {
        "finding_type": finding_type, "finding_value": finding_value,
        "mapped": True,
        "techniques": [_describe_technique(t, index) for t in rule["techniques"]],
        "tactics": [_describe_tactic(t, index) for t in rule["tactics"]],
        "data_source": index.get("_source", "static_fallback"),
        "error": None,
    }


# ── Unified-engine finding → finding_type normalization ────────────────────────

_SSL_ISSUE_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("self_signed_cert", "self-signed"),
    ("cert_expired", "expired"),
    ("weak_tls_10", "tlsv1.0"),
    ("weak_tls_11", "tlsv1.1"),
    ("weak_cipher", "weak cipher"),
)

_ENTITY_TYPE_ALIASES: dict[str, str] = {
    "breach": "email_breach",
    "github_exposure": "github_secret_exposed",
}


def finding_type_from_entity(entity: dict) -> str | None:
    """
    Best-effort normalization of a modules/osint/unified_engine.py finding
    (`{type, value, ...}`) into one of _MAPPING_RULES's keys, so scan
    output can be run through map_finding_to_attack() without every
    source needing to know ATT&CK finding_type names directly.

    Returns None when the finding has no corresponding deterministic
    rule — callers should skip it, not treat that as an error.
    """
    entity_type = entity.get("type")
    if entity_type in _MAPPING_RULES:
        return entity_type

    if entity_type == "open_port":
        port = entity.get("port")
        candidate = f"port_{port}_open"
        return candidate if port and candidate in _MAPPING_RULES else None

    if entity_type == "ssl_issue":
        text = str(entity.get("value") or "").lower()
        for finding_type, keyword in _SSL_ISSUE_KEYWORDS:
            if keyword in text:
                return finding_type
        return None

    return _ENTITY_TYPE_ALIASES.get(entity_type)


async def map_findings_to_attack(entities: list[dict]) -> list[dict]:
    """
    Batch-map a list of unified-engine findings/entities to ATT&CK,
    silently skipping any entity with no deterministic rule
    (finding_type_from_entity() returns None for it).

    Returns a list of map_finding_to_attack() results (mapped=True only).
    Never raises.
    """
    results: list[dict] = []
    for entity in entities or []:
        finding_type = finding_type_from_entity(entity)
        if not finding_type:
            continue
        mapped = await map_finding_to_attack(finding_type, entity.get("value"))
        if mapped.get("mapped"):
            results.append(mapped)
    return results


# ── Attack path generation ──────────────────────────────────────────────────────

async def generate_attack_path(all_findings: list[dict]) -> dict:
    """
    Map every finding in `all_findings` (each `{finding_type,
    finding_value}` or a raw unified-engine `{type, value}` entity) to
    ATT&CK, group the resulting techniques by tactic, and order the
    tactics along the full 14-stage Enterprise kill chain (Reconnaissance
    -> ... -> Impact) — regardless of the order findings were given in.

    Returns {total_findings_analyzed, mapped_findings, attack_path,
    path_length}. Each `attack_path` step is {step, tactic_id,
    tactic_name, techniques, supporting_findings, likelihood} — likelihood
    is a 0-1 heuristic driven by how many findings/distinct techniques
    support that kill-chain stage, not a statistical prediction. Never
    raises.
    """
    mapped_results: list[dict] = []
    for finding in all_findings or []:
        finding_type = finding.get("finding_type") or finding_type_from_entity(finding)
        if not finding_type:
            continue
        finding_value = finding.get("finding_value", finding.get("value"))
        mapped = await map_finding_to_attack(finding_type, finding_value)
        if mapped.get("mapped"):
            mapped_results.append(mapped)

    by_tactic: dict[str, dict] = {}
    for mapped in mapped_results:
        for tactic in mapped.get("tactics") or []:
            tactic_id = tactic.get("id")
            if not tactic_id:
                continue
            bucket = by_tactic.setdefault(tactic_id, {"tactic": tactic, "techniques": [], "finding_count": 0})
            bucket["techniques"].extend(mapped.get("techniques") or [])
            bucket["finding_count"] += 1

    total_mapped = len(mapped_results) or 1
    attack_path: list[dict] = []
    for tactic_id in _KILL_CHAIN_ORDER:
        bucket = by_tactic.get(tactic_id)
        if not bucket:
            continue
        deduped: dict[str, dict] = {}
        for technique in bucket["techniques"]:
            deduped.setdefault(technique["id"], technique)
        techniques = list(deduped.values())
        likelihood = round(min(1.0, bucket["finding_count"] / total_mapped + 0.1 * (len(techniques) - 1)), 2)
        attack_path.append({
            "step": len(attack_path) + 1,
            "tactic_id": tactic_id,
            "tactic_name": bucket["tactic"].get("name"),
            "techniques": techniques,
            "supporting_findings": bucket["finding_count"],
            "likelihood": likelihood,
        })

    return {
        "total_findings_analyzed": len(all_findings or []),
        "mapped_findings": len(mapped_results),
        "attack_path": attack_path,
        "path_length": len(attack_path),
    }
