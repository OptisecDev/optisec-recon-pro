"""Global Threat Intelligence Feed — federated IOC sharing, threat scoring, attack correlation, live threat map."""
import json
import hashlib
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

DATA_FILE = Path("data/global_threat_feed.json")

# ── Threat Feed Sources (simulated OSINT/commercial feeds) ────────────────────

FEED_SOURCES = [
    {"id": "OPTISEC-GLOBAL",  "name": "OPTISEC Global Network",       "type": "internal",   "reliability": 0.95},
    {"id": "ABUSE-CH",        "name": "Abuse.ch ThreatFox",           "type": "open",       "reliability": 0.90},
    {"id": "ALIENVAULT-OTX",  "name": "AlienVault OTX",               "type": "open",       "reliability": 0.85},
    {"id": "MISP-COMMUNITY",  "name": "MISP Threat Sharing",          "type": "community",  "reliability": 0.88},
    {"id": "CISA-KEV",        "name": "CISA Known Exploited Vulns",   "type": "government", "reliability": 0.98},
    {"id": "SPAMHAUS",        "name": "Spamhaus DROP/EDROP",          "type": "commercial", "reliability": 0.92},
    {"id": "FEODO-TRACKER",   "name": "Feodo Tracker (Botnet C2)",    "type": "open",       "reliability": 0.93},
    {"id": "URLHAUS",         "name": "URLhaus Malware URLs",         "type": "open",       "reliability": 0.89},
    {"id": "CIRCL-LU",        "name": "CIRCL Luxembourg",             "type": "government", "reliability": 0.91},
    {"id": "MANDIANT",        "name": "Mandiant Threat Intelligence", "type": "commercial", "reliability": 0.96},
]

# ── Simulated live IOC stream ─────────────────────────────────────────────────
# NOTE: URLHAUS entries used to be hardcoded here too. They've been removed —
# real URLhaus IOCs now come from the local Ioc table via
# fetch_real_urlhaus_iocs() below, sourced from modules/ioc/scheduler.py's
# periodic sync (Phase 3). Every other source in this list (ABUSE-CH,
# CISA-KEV, FEODO-TRACKER, etc.) is still fabricated sample data — untouched.

_SAMPLE_IOCS = [
    {"type": "ip",         "value": "185.234.216.45", "malware": "Cobalt Strike",    "confidence": 95, "source": "FEODO-TRACKER"},
    {"type": "ip",         "value": "91.108.4.10",    "malware": "Emotet",           "confidence": 92, "source": "ABUSE-CH"},
    {"type": "domain",     "value": "evil-c2-domain.ru", "malware": "Qbot",         "confidence": 88, "source": "ALIENVAULT-OTX"},
    {"type": "hash_sha256","value": "a9f2e1b3c5d7890f1a2b3c4d5e6f7890a1b2c3d4e5f67890a1b2c3d4e5f67890",
     "malware": "WannaCry",     "confidence": 99, "source": "MISP-COMMUNITY"},
    {"type": "ip",         "value": "5.188.206.14",   "malware": "TrickBot",         "confidence": 90, "source": "SPAMHAUS"},
    {"type": "cve",        "value": "CVE-2021-44228", "malware": "Log4Shell",        "confidence": 99, "source": "CISA-KEV"},
    {"type": "cve",        "value": "CVE-2023-44487", "malware": "HTTP/2 Rapid Reset","confidence": 98,"source": "CISA-KEV"},
    {"type": "domain",     "value": "malware-distribution.xyz", "malware": "AsyncRAT","confidence": 85,"source": "CIRCL-LU"},
    {"type": "hash_md5",   "value": "d41d8cd98f00b204e9800998ecf8427e", "malware": "Mirai", "confidence": 88, "source": "ALIENVAULT-OTX"},
    {"type": "ip",         "value": "103.43.75.1",    "malware": "APT41 Infrastructure","confidence": 94,"source": "MANDIANT"},
    {"type": "ip",         "value": "178.250.240.10", "malware": "Lazarus Group",    "confidence": 96, "source": "MANDIANT"},
    {"type": "domain",     "value": "update-microsoft-security.net","malware":"Phishing","confidence": 82,"source": "OPTISEC-GLOBAL"},
    {"type": "hash_sha256","value": "3f5a2e9b0c1d4e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f",
     "malware": "Ryuk",         "confidence": 91, "source": "MISP-COMMUNITY"},
    {"type": "ip",         "value": "62.75.154.99",   "malware": "BlackMatter",      "confidence": 87, "source": "FEODO-TRACKER"},
    {"type": "cve",        "value": "CVE-2022-30190", "malware": "Follina MSDT",     "confidence": 97, "source": "CISA-KEV"},
    {"type": "cve",        "value": "CVE-2024-3400",  "malware": "PAN-OS Zero-Day",  "confidence": 99, "source": "CISA-KEV"},
    {"type": "domain",     "value": "apt28-infrastructure.eu", "malware": "APT28",   "confidence": 93, "source": "MANDIANT"},
    {"type": "ip",         "value": "37.120.222.5",   "malware": "LockBit",          "confidence": 89, "source": "ABUSE-CH"},
]

# ── Threat Map Nodes (global attack origins/targets) ─────────────────────────

THREAT_MAP_POINTS = [
    {"lat": 55.7558,  "lon": 37.6176,  "country": "Russia",       "code": "RU", "attacks_per_hour": 847,  "threat_level": "critical"},
    {"lat": 39.9042,  "lon": 116.4074, "country": "China",        "code": "CN", "attacks_per_hour": 1203, "threat_level": "critical"},
    {"lat": 35.6892,  "lon": 51.3890,  "country": "Iran",         "code": "IR", "attacks_per_hour": 312,  "threat_level": "high"},
    {"lat": 37.5665,  "lon": 126.9780, "country": "North Korea",  "code": "KP", "attacks_per_hour": 189,  "threat_level": "critical"},
    {"lat": 40.7128,  "lon": -74.0060, "country": "USA",          "code": "US", "attacks_per_hour": 2341, "threat_level": "high"},
    {"lat": 51.5074,  "lon": -0.1278,  "country": "UK",           "code": "GB", "attacks_per_hour": 234,  "threat_level": "medium"},
    {"lat": 52.5200,  "lon": 13.4050,  "country": "Germany",      "code": "DE", "attacks_per_hour": 198,  "threat_level": "medium"},
    {"lat": 48.8566,  "lon": 2.3522,   "country": "France",       "code": "FR", "attacks_per_hour": 167,  "threat_level": "medium"},
    {"lat": 35.6762,  "lon": 139.6503, "country": "Japan",        "code": "JP", "attacks_per_hour": 145,  "threat_level": "medium"},
    {"lat": -33.8688, "lon": 151.2093, "country": "Australia",    "code": "AU", "attacks_per_hour": 89,   "threat_level": "low"},
    {"lat": 28.6139,  "lon": 77.2090,  "country": "India",        "code": "IN", "attacks_per_hour": 421,  "threat_level": "high"},
    {"lat": -23.5505, "lon": -46.6333, "country": "Brazil",       "code": "BR", "attacks_per_hour": 276,  "threat_level": "high"},
    {"lat": 43.6532,  "lon": -79.3832, "country": "Canada",       "code": "CA", "attacks_per_hour": 134,  "threat_level": "medium"},
    {"lat": 41.9028,  "lon": 12.4964,  "country": "Italy",        "code": "IT", "attacks_per_hour": 123,  "threat_level": "medium"},
    {"lat": 40.4168,  "lon": -3.7038,  "country": "Spain",        "code": "ES", "attacks_per_hour": 98,   "threat_level": "low"},
    {"lat": 25.2048,  "lon": 55.2708,  "country": "UAE",          "code": "AE", "attacks_per_hour": 145,  "threat_level": "medium"},
    {"lat": 32.0853,  "lon": 34.7818,  "country": "Israel",       "code": "IL", "attacks_per_hour": 112,  "threat_level": "medium"},
    {"lat": 59.9139,  "lon": 10.7522,  "country": "Norway",       "code": "NO", "attacks_per_hour": 34,   "threat_level": "low"},
    {"lat": -34.6037, "lon": -58.3816, "country": "Argentina",    "code": "AR", "attacks_per_hour": 67,   "threat_level": "low"},
    {"lat": 19.4326,  "lon": -99.1332, "country": "Mexico",       "code": "MX", "attacks_per_hour": 189,  "threat_level": "medium"},
]

# ── Attack Pattern Correlation ────────────────────────────────────────────────

ATTACK_CAMPAIGNS = [
    {
        "id": "CAMP-2024-001",
        "name": "Operation GhostNet Redux",
        "actor": "APT41",
        "start_date": "2024-01-15",
        "status": "active",
        "target_sectors": ["Healthcare", "Finance", "Government"],
        "ioc_count": 847,
        "countries_targeted": ["US", "UK", "DE", "AU", "JP"],
        "techniques": ["T1190", "T1505.003", "T1486", "T1041"],
        "confidence": 87,
        "description": "Large-scale intrusion campaign targeting healthcare records and financial data.",
    },
    {
        "id": "CAMP-2024-002",
        "name": "DarkVortex Ransomware Wave",
        "actor": "LockBit 3.0",
        "start_date": "2024-03-08",
        "status": "active",
        "target_sectors": ["Manufacturing", "Education", "Legal"],
        "ioc_count": 1240,
        "countries_targeted": ["US", "CA", "AU", "GB", "FR"],
        "techniques": ["T1566.001", "T1486", "T1490", "T1048"],
        "confidence": 94,
        "description": "Aggressive double-extortion ransomware campaign with data leak threats.",
    },
    {
        "id": "CAMP-2024-003",
        "name": "CloudSerpent Supply Chain",
        "actor": "APT29 (NOBELIUM)",
        "start_date": "2024-02-20",
        "status": "active",
        "target_sectors": ["Technology", "Defense", "Think Tanks"],
        "ioc_count": 312,
        "countries_targeted": ["US", "EU", "UA"],
        "techniques": ["T1195.001", "T1078", "T1573", "T1105"],
        "confidence": 91,
        "description": "Sophisticated supply chain attack targeting cloud service providers and MSPs.",
    },
    {
        "id": "CAMP-2024-004",
        "name": "IronFist Critical Infrastructure",
        "actor": "Sandworm (GRU)",
        "start_date": "2024-04-01",
        "status": "monitoring",
        "target_sectors": ["Energy", "Utilities", "OT/ICS"],
        "ioc_count": 189,
        "countries_targeted": ["UA", "PL", "DE", "US"],
        "techniques": ["T1485", "T1561", "T1490", "T1499"],
        "confidence": 78,
        "description": "Destructive campaign targeting European energy infrastructure.",
    },
]


def _load_data() -> dict:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    if DATA_FILE.exists():
        try:
            return json.loads(DATA_FILE.read_text())
        except Exception:
            pass
    return {
        "ioc_feed": [],
        "shared_iocs": [],
        "nodes": [],
        "feed_stats": {"total_iocs": 0, "shared_today": 0, "active_nodes": 0},
    }


def _save_data(data: dict) -> None:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    DATA_FILE.write_text(json.dumps(data, indent=2, default=str))


def get_live_ioc_feed(limit: int = 50, urlhaus_iocs: Optional[List[dict]] = None) -> dict:
    """Return the current live IOC feed with aggregated threat scores.

    urlhaus_iocs: real abuse.ch URLhaus indicators (see
    fetch_real_urlhaus_iocs()), in the same raw shape as a _SAMPLE_IOCS
    entry. Callers with a DB session (the threat-feed/threat-sharing
    routers) fetch these themselves and pass them in — this function stays
    DB-free so it's still callable with no arguments, same as before.
    """
    data = _load_data()

    # Merge static + stored + real URLhaus IOCs
    all_iocs = list(_SAMPLE_IOCS) + list(urlhaus_iocs or [])
    for stored in data.get("shared_iocs", [])[:20]:
        all_iocs.insert(0, stored)

    # Add threat scoring
    scored = []
    for ioc in all_iocs[:limit]:
        scored.append({
            **ioc,
            "id": hashlib.md5(f"{ioc['type']}:{ioc['value']}".encode()).hexdigest()[:10],
            "threat_score": _aggregate_threat_score(ioc),
            "first_seen": _fake_date(-random.randint(1, 90)),
            "last_seen": _fake_date(-random.randint(0, 7)),
            "tags": _generate_tags(ioc),
            "tlp": random.choice(["WHITE", "GREEN", "AMBER", "RED"]),
        })

    total_score = sum(i["threat_score"] for i in scored) / len(scored) if scored else 0

    return {
        "iocs": scored,
        "total": len(scored),
        "feed_sources": FEED_SOURCES,
        "global_threat_level": _global_threat_level(total_score),
        "updated_at": datetime.utcnow().isoformat(),
        "stats": {
            "critical_iocs": sum(1 for i in scored if i["threat_score"] >= 80),
            "high_iocs": sum(1 for i in scored if 60 <= i["threat_score"] < 80),
            "medium_iocs": sum(1 for i in scored if 40 <= i["threat_score"] < 60),
            "by_type": _count_by_type(scored),
            "by_source": _count_by_source(scored),
        },
    }


async def fetch_real_urlhaus_iocs(db: "AsyncSession", limit: int = 20) -> List[dict]:
    """Real abuse.ch URLhaus indicators from the local Ioc table (populated
    by modules/ioc/scheduler.py's periodic sync or a manual POST
    /api/iocs/sync/urlhaus), reshaped into the same raw dict shape a
    _SAMPLE_IOCS entry has so get_live_ioc_feed() can score/tag them
    identically to the fabricated rows. Returns [] if nothing has been
    synced yet (e.g. no URLHAUS_API_KEY configured) — that's a normal,
    expected state, not an error.
    """
    from modules.ioc.ioc_engine import IOCRepository

    repo = IOCRepository(db)
    rows = await repo.list_active(ioc_type="url", source="urlhaus", limit=limit)
    return [
        {
            "type": "url",
            "value": row.ioc_value,
            "malware": _malware_from_tags(row.tags),
            "confidence": int(row.confidence_score),
            # Uppercase to match FEED_SOURCES' "URLHAUS" id (the Ioc table
            # itself stores source="urlhaus", lowercase, per sync_from_urlhaus).
            "source": "URLHAUS",
        }
        for row in rows
    ]


def _malware_from_tags(tags: Optional[List[str]]) -> str:
    for tag in tags or []:
        if tag.startswith("malware_family:"):
            return tag.split(":", 1)[1]
    return "Unknown"


def _aggregate_threat_score(ioc: dict) -> int:
    base = ioc.get("confidence", 50)
    source = next((s for s in FEED_SOURCES if s["id"] == ioc.get("source", "")), None)
    reliability = source["reliability"] if source else 0.7
    malware = ioc.get("malware", "")
    multiplier = 1.2 if any(apt in malware for apt in ["APT", "Lazarus", "Sandworm", "HAFNIUM"]) else 1.0
    return min(100, int(base * reliability * multiplier))


def _global_threat_level(avg_score: float) -> str:
    if avg_score >= 80:
        return "CRITICAL"
    if avg_score >= 65:
        return "HIGH"
    if avg_score >= 45:
        return "ELEVATED"
    return "GUARDED"


def _generate_tags(ioc: dict) -> List[str]:
    tags = [ioc.get("malware", "unknown").lower().replace(" ", "-")]
    if ioc["type"] in ("ip", "domain"):
        tags.append("network-indicator")
    if ioc["type"].startswith("hash"):
        tags.append("file-indicator")
    if ioc["type"] == "cve":
        tags.append("vulnerability")
    if "apt" in ioc.get("malware", "").lower():
        tags.append("nation-state")
    return tags


def _count_by_type(iocs: list) -> dict:
    counts: dict = {}
    for ioc in iocs:
        t = ioc["type"]
        counts[t] = counts.get(t, 0) + 1
    return counts


def _count_by_source(iocs: list) -> dict:
    counts: dict = {}
    for ioc in iocs:
        s = ioc.get("source", "unknown")
        counts[s] = counts.get(s, 0) + 1
    return counts


def _fake_date(delta_days: int) -> str:
    dt = datetime.utcnow() + timedelta(days=delta_days)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def submit_ioc(ioc_type: str, value: str, malware: str, confidence: int, tlp: str = "AMBER") -> dict:
    """Submit a new IOC to the shared feed."""
    data = _load_data()
    ioc = {
        "id": hashlib.md5(f"{ioc_type}:{value}:{datetime.utcnow().isoformat()}".encode()).hexdigest()[:10],
        "type": ioc_type,
        "value": value,
        "malware": malware,
        "confidence": min(100, max(0, confidence)),
        "source": "OPTISEC-GLOBAL",
        "tlp": tlp,
        "submitted_at": datetime.utcnow().isoformat(),
        "threat_score": min(100, int(confidence * 0.95)),
    }
    data["shared_iocs"].insert(0, ioc)
    data["shared_iocs"] = data["shared_iocs"][:200]
    data["feed_stats"]["total_iocs"] = data["feed_stats"].get("total_iocs", 0) + 1
    data["feed_stats"]["shared_today"] = data["feed_stats"].get("shared_today", 0) + 1
    _save_data(data)
    return ioc


def get_threat_map() -> dict:
    """Return geo data for the live threat map visualization."""
    # Add some randomness to simulate live data
    points = []
    for p in THREAT_MAP_POINTS:
        points.append({
            **p,
            "attacks_per_hour": max(0, p["attacks_per_hour"] + random.randint(-50, 50)),
            "active_campaigns": random.randint(0, 5),
        })

    return {
        "points": points,
        "total_attacks_per_hour": sum(p["attacks_per_hour"] for p in points),
        "updated_at": datetime.utcnow().isoformat(),
        "top_origin": max(points, key=lambda x: x["attacks_per_hour"])["country"],
    }


def get_campaigns() -> List[dict]:
    return ATTACK_CAMPAIGNS


def correlate_iocs(ioc_list: List[dict]) -> dict:
    """Correlate submitted IOCs against known campaigns."""
    matches = []
    for ioc in ioc_list:
        for campaign in ATTACK_CAMPAIGNS:
            if ioc.get("value", "").lower() in [i.get("value", "").lower() for i in _SAMPLE_IOCS
                                                 if i.get("malware", "").lower() in campaign["actor"].lower()
                                                 or campaign["actor"].lower() in i.get("malware", "").lower()]:
                matches.append({
                    "ioc": ioc,
                    "campaign": campaign["name"],
                    "actor": campaign["actor"],
                    "confidence": campaign["confidence"],
                })
                break

    # Pattern analysis
    ip_count = sum(1 for i in ioc_list if i.get("type") == "ip")
    domain_count = sum(1 for i in ioc_list if i.get("type") == "domain")
    hash_count = sum(1 for i in ioc_list if "hash" in i.get("type", ""))

    return {
        "submitted_count": len(ioc_list),
        "campaign_matches": matches,
        "pattern_analysis": {
            "ip_indicators": ip_count,
            "domain_indicators": domain_count,
            "file_indicators": hash_count,
            "likely_ttps": _infer_ttps(ioc_list),
        },
        "attribution_confidence": (len(matches) / max(len(ioc_list), 1)) * 100,
        "correlated_at": datetime.utcnow().isoformat(),
    }


def _infer_ttps(ioc_list: List[dict]) -> List[str]:
    ttps = []
    types = {i.get("type") for i in ioc_list}
    if "ip" in types:
        ttps.extend(["T1071 - App Layer Protocol", "T1090 - Proxy"])
    if "domain" in types:
        ttps.extend(["T1568.002 - DGA", "T1071.004 - DNS"])
    if any("hash" in t for t in types):
        ttps.extend(["T1027 - Obfuscated Files", "T1587.001 - Malware"])
    if "cve" in types:
        ttps.extend(["T1190 - Exploit Public-Facing App", "T1211 - Defense Evasion"])
    return list(set(ttps))


def get_feed_stats() -> dict:
    data = _load_data()
    return {
        **data.get("feed_stats", {}),
        "feed_sources": len(FEED_SOURCES),
        "active_campaigns": len([c for c in ATTACK_CAMPAIGNS if c["status"] == "active"]),
        "sample_ioc_count": len(_SAMPLE_IOCS),
        "shared_ioc_count": len(data.get("shared_iocs", [])),
        "updated_at": datetime.utcnow().isoformat(),
    }
