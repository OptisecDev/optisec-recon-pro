"""IOC Correlation Engine — links IOCs across types, detects shared threat patterns, computes aggregated threat scores."""
import hashlib
import json
import os
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from modules.threat_intel.global_feed import _SAMPLE_IOCS, FEED_SOURCES

DATA_FILE = Path("data/ioc_correlations.json")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")

# ── IOC type buckets ──────────────────────────────────────────────────────────
IP_TYPES     = {"ip", "cidr"}
DOMAIN_TYPES = {"domain", "hostname"}
HASH_TYPES   = {"hash_md5", "hash_sha1", "hash_sha256", "hash_sha512"}
URL_TYPES    = {"url", "uri", "url"}

# Base weight per IOC type (higher = more reliable indicator)
_TYPE_WEIGHT: Dict[str, float] = {
    "hash_sha256": 1.00,
    "hash_sha512": 1.00,
    "hash_sha1":   0.95,
    "hash_md5":    0.90,
    "cve":         1.00,
    "ip":          0.90,
    "domain":      0.85,
    "url":         0.88,
    "cidr":        0.82,
    "mutex":       0.80,
    "yara":        0.90,
    "email":       0.75,
    "filepath":    0.70,
}

_SEVERITY_BANDS = [
    (90, "CRITICAL"),
    (70, "HIGH"),
    (50, "MEDIUM"),
    (30, "LOW"),
    (0,  "INFORMATIONAL"),
]

# Known high-risk threat actors that boost cluster score
_HIGH_RISK_ACTORS = {
    "apt28", "apt29", "apt41", "lazarus group", "cobalt group",
    "fin7", "lockbit", "conti", "blackcat", "alphv",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _severity(score: float) -> str:
    for threshold, label in _SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "INFORMATIONAL"


def _cluster_id(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:12]


def _extract_domain_from_url(url: str) -> Optional[str]:
    m = re.search(r"https?://([^/?\s]+)", url)
    return m.group(1).lower() if m else None


def _ip_subnet(ip: str) -> Optional[str]:
    """Return /24 subnet string for simple infrastructure clustering."""
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".0/24"
    return None


# ── IOC collection ────────────────────────────────────────────────────────────

def _load_otx_iocs() -> List[dict]:
    if not OTX_API_KEY:
        return []
    try:
        from modules.threat_intel.otx_feed import fetch_otx_pulses
        return fetch_otx_pulses(OTX_API_KEY, limit=100)
    except Exception:
        return []


def collect_iocs() -> List[dict]:
    """Merge IOCs from AlienVault OTX and the built-in global feed sample."""
    iocs: List[dict] = []

    # Built-in global feed (always available, normalised)
    for raw in _SAMPLE_IOCS:
        ioc_type = raw.get("type", "unknown")
        value    = raw.get("value", "")
        if not value:
            continue
        iocs.append({
            "id":         hashlib.md5(f"{ioc_type}:{value}".encode()).hexdigest()[:10],
            "type":       ioc_type,
            "value":      value,
            "malware":    raw.get("malware", "Unknown"),
            "confidence": raw.get("confidence", 70),
            "source":     raw.get("source", "OPTISEC-GLOBAL"),
            "adversary":  raw.get("adversary", ""),
            "tags":       raw.get("tags", []),
            "threat_score": raw.get("threat_score", raw.get("confidence", 70)),
        })

    # Live OTX feed (if API key present)
    for otx in _load_otx_iocs():
        iocs.append({
            "id":           otx.get("id", ""),
            "type":         otx.get("type", "unknown"),
            "value":        otx.get("value", ""),
            "malware":      otx.get("malware", "Unknown"),
            "confidence":   otx.get("confidence", 70),
            "source":       "ALIENVAULT-OTX",
            "adversary":    otx.get("adversary", ""),
            "tags":         otx.get("tags", []),
            "threat_score": otx.get("threat_score", 70),
            "pulse_name":   otx.get("pulse_name", ""),
        })

    return iocs


# ── Correlation logic ─────────────────────────────────────────────────────────

def _compute_cluster_score(iocs: List[dict], adversary: str) -> float:
    """Aggregated threat score for a cluster of related IOCs."""
    if not iocs:
        return 0.0

    weighted_sum = 0.0
    weight_total = 0.0
    type_diversity = len({i["type"] for i in iocs})

    for ioc in iocs:
        w = _TYPE_WEIGHT.get(ioc["type"], 0.70)
        weighted_sum += ioc.get("threat_score", ioc.get("confidence", 70)) * w
        weight_total += w

    base = weighted_sum / weight_total if weight_total else 0.0

    # Boost for multi-vector (more IOC types = broader infrastructure visibility)
    diversity_bonus = min(10, (type_diversity - 1) * 3)

    # Boost for attributed adversary
    actor_bonus = 8 if adversary and adversary.lower() in _HIGH_RISK_ACTORS else (4 if adversary else 0)

    # Boost for cluster size (more correlated IOCs → higher confidence)
    size_bonus = min(8, (len(iocs) - 1) * 1.5)

    return min(100.0, base + diversity_bonus + actor_bonus + size_bonus)


def correlate_iocs(iocs: List[dict]) -> List[dict]:
    """
    Group IOCs into correlation clusters using three strategies:
      1. Malware-family grouping  (primary)
      2. Adversary/threat-actor grouping
      3. Shared network infrastructure (same /24 subnet or domain←URL)
    """
    # ── Strategy 1: malware family ───────────────────────────────────────────
    by_malware: Dict[str, List[dict]] = defaultdict(list)
    for ioc in iocs:
        key = (ioc.get("malware") or "Unknown").strip()
        by_malware[key].append(ioc)

    # ── Strategy 2: adversary attribution ────────────────────────────────────
    by_adversary: Dict[str, List[dict]] = defaultdict(list)
    for ioc in iocs:
        adv = (ioc.get("adversary") or "").strip()
        if adv:
            by_adversary[adv].append(ioc)

    # ── Strategy 3: shared network infrastructure ─────────────────────────────
    subnet_map: Dict[str, List[dict]]  = defaultdict(list)
    domain_map: Dict[str, List[dict]]  = defaultdict(list)
    for ioc in iocs:
        if ioc["type"] in IP_TYPES:
            subnet = _ip_subnet(ioc["value"])
            if subnet:
                subnet_map[subnet].append(ioc)
        elif ioc["type"] in DOMAIN_TYPES:
            domain_map[ioc["value"].lower()].append(ioc)
        elif ioc["type"] in URL_TYPES:
            d = _extract_domain_from_url(ioc["value"])
            if d and d in domain_map:
                domain_map[d].extend([ioc])

    # ── Build clusters ────────────────────────────────────────────────────────
    clusters: List[dict] = []

    # Malware clusters (min 1 IOC — every family gets a cluster)
    for malware_name, members in sorted(by_malware.items()):
        # Find unique adversaries in this cluster
        adversaries = list({i.get("adversary", "") for i in members if i.get("adversary")})
        adversary   = adversaries[0] if adversaries else ""

        # IOC-type breakdown
        type_counts: Dict[str, int] = defaultdict(int)
        for m in members:
            type_counts[m["type"]] += 1

        # Relationships: cross-link different IOC types within same family
        relationships = _build_relationships(members)

        score = _compute_cluster_score(members, adversary)

        clusters.append({
            "cluster_id":   _cluster_id("malware", malware_name),
            "name":         malware_name,
            "strategy":     "malware_family",
            "ioc_count":    len(members),
            "ioc_types":    dict(type_counts),
            "adversary":    adversary,
            "sources":      list({i["source"] for i in members}),
            "threat_score": round(score, 1),
            "severity":     _severity(score),
            "iocs":         members,
            "relationships": relationships,
            "patterns":     _detect_patterns(members),
        })

    # Adversary clusters (only if ≥2 IOCs)
    for adv_name, members in sorted(by_adversary.items()):
        if len(members) < 2:
            continue
        type_counts = defaultdict(int)
        for m in members:
            type_counts[m["type"]] += 1
        score = _compute_cluster_score(members, adv_name)
        clusters.append({
            "cluster_id":   _cluster_id("adversary", adv_name),
            "name":         f"[Actor] {adv_name}",
            "strategy":     "adversary",
            "ioc_count":    len(members),
            "ioc_types":    dict(type_counts),
            "adversary":    adv_name,
            "sources":      list({i["source"] for i in members}),
            "threat_score": round(score, 1),
            "severity":     _severity(score),
            "iocs":         members,
            "relationships": _build_relationships(members),
            "patterns":     _detect_patterns(members),
        })

    # Infrastructure clusters (/24 subnets with ≥2 IPs)
    for subnet, members in sorted(subnet_map.items()):
        if len(members) < 2:
            continue
        adversaries = list({i.get("adversary", "") for i in members if i.get("adversary")})
        adversary   = adversaries[0] if adversaries else ""
        score       = _compute_cluster_score(members, adversary)
        clusters.append({
            "cluster_id":   _cluster_id("subnet", subnet),
            "name":         f"[Infra] {subnet}",
            "strategy":     "network_infrastructure",
            "ioc_count":    len(members),
            "ioc_types":    {"ip": len(members)},
            "adversary":    adversary,
            "sources":      list({i["source"] for i in members}),
            "threat_score": round(score, 1),
            "severity":     _severity(score),
            "iocs":         members,
            "relationships": _build_relationships(members),
            "patterns":     _detect_patterns(members),
        })

    # Sort by threat_score descending
    clusters.sort(key=lambda c: c["threat_score"], reverse=True)
    return clusters


def _build_relationships(iocs: List[dict]) -> List[dict]:
    """Cross-link IOCs of different types that share the same cluster."""
    rels: List[dict] = []
    for i, a in enumerate(iocs):
        for b in iocs[i + 1:]:
            if a["type"] == b["type"]:
                continue  # only cross-type links
            rel_type = _relationship_label(a["type"], b["type"])
            rels.append({
                "source_id":   a["id"],
                "source_type": a["type"],
                "source_val":  a["value"],
                "target_id":   b["id"],
                "target_type": b["type"],
                "target_val":  b["value"],
                "relation":    rel_type,
            })
            if len(rels) >= 50:  # cap per cluster to avoid bloat
                return rels
    return rels


def _relationship_label(type_a: str, type_b: str) -> str:
    pair = frozenset([type_a, type_b])
    if pair <= (IP_TYPES | DOMAIN_TYPES):
        return "resolves_to"
    if "url" in pair and bool(pair & DOMAIN_TYPES):
        return "hosted_on"
    if "url" in pair and bool(pair & IP_TYPES):
        return "resolves_to"
    if bool(pair & HASH_TYPES) and bool(pair & (IP_TYPES | DOMAIN_TYPES)):
        return "communicates_with"
    if bool(pair & HASH_TYPES) and bool(pair & URL_TYPES):
        return "downloaded_from"
    if "cve" in pair:
        return "exploited_by"
    return "related_to"


def _detect_patterns(iocs: List[dict]) -> List[str]:
    """Detect behavioural/infrastructure patterns in a cluster."""
    patterns: List[str] = []
    types = {i["type"] for i in iocs}

    if bool(types & IP_TYPES) and bool(types & DOMAIN_TYPES):
        patterns.append("multi-vector: IP + domain infrastructure")
    if bool(types & HASH_TYPES) and bool(types & (IP_TYPES | DOMAIN_TYPES)):
        patterns.append("payload delivery: file hash + C2 infrastructure")
    if bool(types & URL_TYPES) and bool(types & HASH_TYPES):
        patterns.append("malware distribution: download URL + file hash")
    if "cve" in types:
        patterns.append("vulnerability exploitation campaign")
    if len(types & HASH_TYPES) > 1:
        patterns.append("multi-hash: same file across hash types")
    if len([i for i in iocs if i["type"] in IP_TYPES]) >= 3:
        patterns.append("botnet / distributed C2 infrastructure")
    if any(i.get("adversary") for i in iocs):
        patterns.append("attributed threat actor activity")
    sources = {i["source"] for i in iocs}
    if len(sources) > 1:
        patterns.append(f"cross-source corroboration ({len(sources)} feeds)")

    return patterns or ["single-indicator cluster"]


# ── Main entry point ──────────────────────────────────────────────────────────

def run_correlation(save: bool = True) -> dict:
    """
    Run the full IOC correlation pipeline and optionally persist results to
    data/ioc_correlations.json.

    Returns a dict with summary stats and the full cluster list.
    """
    iocs     = collect_iocs()
    clusters = correlate_iocs(iocs)

    # Summary statistics
    total_iocs       = len(iocs)
    total_clusters   = len(clusters)
    critical_clusters = [c for c in clusters if c["severity"] == "CRITICAL"]
    high_clusters     = [c for c in clusters if c["severity"] == "HIGH"]
    avg_score         = round(
        sum(c["threat_score"] for c in clusters) / total_clusters, 1
    ) if total_clusters else 0.0

    # IOC type breakdown across all clusters (de-duplicated)
    seen: set = set()
    type_summary: Dict[str, int] = defaultdict(int)
    for ioc in iocs:
        key = f"{ioc['type']}:{ioc['value']}"
        if key not in seen:
            seen.add(key)
            type_summary[ioc["type"]] += 1

    payload = {
        "generated_at":      datetime.utcnow().isoformat() + "Z",
        "otx_enabled":       bool(OTX_API_KEY),
        "total_iocs":        total_iocs,
        "unique_iocs":       len(seen),
        "total_clusters":    total_clusters,
        "critical_clusters": len(critical_clusters),
        "high_clusters":     len(high_clusters),
        "average_score":     avg_score,
        "ioc_type_summary":  dict(type_summary),
        "sources_active":    list({i["source"] for i in iocs}),
        "clusters":          clusters,
    }

    if save:
        DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        DATA_FILE.write_text(json.dumps(payload, indent=2, default=str))

    return payload


def load_cached() -> Optional[dict]:
    """Return the last persisted correlation result, or None if not available."""
    if DATA_FILE.exists():
        try:
            return json.loads(DATA_FILE.read_text())
        except Exception:
            return None
    return None
