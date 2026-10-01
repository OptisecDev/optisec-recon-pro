"""Global Threat Intelligence Feed — federated IOC sharing, threat scoring, attack correlation, live threat map."""
import asyncio
import json
import hashlib
import logging
import random
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

DATA_FILE = Path("data/global_threat_feed.json")
GEO_CACHE_FILE = Path("data/threat_map_geo_cache.json")
GEO_CACHE_TTL = 12 * 3600  # geolocation is stable enough not to re-query ip-api.com every page load

# ── Threat Feed Sources (simulated OSINT/commercial feeds) ────────────────────

# is_sample=False means this source's IOCs are live/real (currently only
# URLHAUS, synced via modules/ioc/scheduler.py — see fetch_real_urlhaus_iocs()
# below). Every other source here is a label on fabricated _SAMPLE_IOCS
# entries below, not an actual live feed integration, so it carries
# is_sample=True in both this catalog and on every IOC tagged with it.
FEED_SOURCES = [
    {"id": "OPTISEC-GLOBAL",  "name": "OPTISEC Global Network",       "type": "internal",   "reliability": 0.95, "is_sample": True},
    {"id": "ABUSE-CH",        "name": "Abuse.ch ThreatFox",           "type": "open",       "reliability": 0.90, "is_sample": True},
    {"id": "ALIENVAULT-OTX",  "name": "AlienVault OTX",               "type": "open",       "reliability": 0.85, "is_sample": True},
    {"id": "MISP-COMMUNITY",  "name": "MISP Threat Sharing",          "type": "community",  "reliability": 0.88, "is_sample": True},
    {"id": "CISA-KEV",        "name": "CISA Known Exploited Vulns",   "type": "government", "reliability": 0.98, "is_sample": True},
    {"id": "SPAMHAUS",        "name": "Spamhaus DROP/EDROP",          "type": "commercial", "reliability": 0.92, "is_sample": True},
    {"id": "FEODO-TRACKER",   "name": "Feodo Tracker (Botnet C2)",    "type": "open",       "reliability": 0.93, "is_sample": True},
    {"id": "URLHAUS",         "name": "URLhaus Malware URLs",         "type": "open",       "reliability": 0.89, "is_sample": False},
    {"id": "CIRCL-LU",        "name": "CIRCL Luxembourg",             "type": "government", "reliability": 0.91, "is_sample": True},
    {"id": "MANDIANT",        "name": "Mandiant Threat Intelligence", "type": "commercial", "reliability": 0.96, "is_sample": True},
]

# ── Simulated live IOC stream ─────────────────────────────────────────────────
# NOTE: URLHAUS entries used to be hardcoded here too. They've been removed —
# real URLhaus IOCs now come from the local Ioc table via
# fetch_real_urlhaus_iocs() below, sourced from modules/ioc/scheduler.py's
# periodic sync (Phase 3). Every other source in this list (ABUSE-CH,
# CISA-KEV, FEODO-TRACKER, etc.) is still fabricated sample data — untouched.

# Indicator VALUES below are documentation-safe placeholders, not real-world
# indicators: IPs are drawn from the RFC 5737 documentation ranges
# (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), domains from RFC 2606
# reserved names (example.com/.net/.org, *.test), and hashes are obviously
# synthetic patterns (deadbeef/cafebabe/abadcafe repeated) rather than any
# real file's digest — none attributable to a real organization or, for the
# hashes, colliding with a real malware sample or (in the prior MD5 row's
# case) the empty file. Threat-actor/malware-family NAMES are kept as
# illustrative labels; only the indicator values themselves are placeholders.
# Public CVE IDs (Log4Shell etc.) are real, public facts and are unchanged.
_SAMPLE_IOCS = [
    {"type": "ip",         "value": "192.0.2.10",     "malware": "Cobalt Strike",    "confidence": 95, "source": "FEODO-TRACKER"},
    {"type": "ip",         "value": "192.0.2.55",     "malware": "Emotet",           "confidence": 92, "source": "ABUSE-CH"},
    {"type": "domain",     "value": "c2-domain-sample.test", "malware": "Qbot",      "confidence": 88, "source": "ALIENVAULT-OTX"},
    {"type": "hash_sha256","value": "deadbeef" * 8,
     "malware": "WannaCry",     "confidence": 99, "source": "MISP-COMMUNITY"},
    {"type": "ip",         "value": "198.51.100.23",  "malware": "TrickBot",         "confidence": 90, "source": "SPAMHAUS"},
    {"type": "cve",        "value": "CVE-2021-44228", "malware": "Log4Shell",        "confidence": 99, "source": "CISA-KEV"},
    {"type": "cve",        "value": "CVE-2023-44487", "malware": "HTTP/2 Rapid Reset","confidence": 98,"source": "CISA-KEV"},
    {"type": "domain",     "value": "malware-distribution.example.net", "malware": "AsyncRAT","confidence": 85,"source": "CIRCL-LU"},
    {"type": "hash_md5",   "value": "cafebabe" * 4, "malware": "Mirai", "confidence": 88, "source": "ALIENVAULT-OTX"},
    {"type": "ip",         "value": "203.0.113.5",    "malware": "APT41 Infrastructure","confidence": 94,"source": "MANDIANT"},
    {"type": "ip",         "value": "203.0.113.80",   "malware": "Lazarus Group",    "confidence": 96, "source": "MANDIANT"},
    {"type": "domain",     "value": "update-security-notice.example.org","malware":"Phishing","confidence": 82,"source": "OPTISEC-GLOBAL"},
    {"type": "hash_sha256","value": "abadcafe" * 8,
     "malware": "Ryuk",         "confidence": 91, "source": "MISP-COMMUNITY"},
    {"type": "ip",         "value": "198.51.100.77",  "malware": "BlackMatter",      "confidence": 87, "source": "FEODO-TRACKER"},
    {"type": "cve",        "value": "CVE-2022-30190", "malware": "Follina MSDT",     "confidence": 97, "source": "CISA-KEV"},
    {"type": "cve",        "value": "CVE-2024-3400",  "malware": "PAN-OS Zero-Day",  "confidence": 99, "source": "CISA-KEV"},
    {"type": "domain",     "value": "apt-infrastructure.example.com", "malware": "APT28",   "confidence": 93, "source": "MANDIANT"},
    {"type": "ip",         "value": "203.0.113.200",  "malware": "LockBit",          "confidence": 89, "source": "ABUSE-CH"},
]

# ── Estimated-field disclosure notes ──────────────────────────────────────────
# get_live_ioc_feed() enriches every real IOC (whether from _SAMPLE_IOCS, a
# caller-supplied urlhaus_iocs list, or a previously submit_ioc()'d entry)
# with a TLP classification (random.choice) and first_seen/last_seen dates
# (_fake_date() with a random day offset) that are NOT part of the original
# indicator — the source feed (e.g. OTX, URLhaus) has no such fields at this
# point. Each scored IOC below is tagged with tlp_source/date_source +
# bilingual note so callers/UI can tell these apart from the real fields
# (type, value, malware, confidence, source) that pass through unmodified.
# Note: OTX-sourced IOCs fetched directly via modules/threat_intel/otx_feed.py
# carry *real* tlp/first_seen/last_seen from the OTX API and never flow
# through this function, so they are never tagged.
IOC_ESTIMATED_NOTE_EN = (
    "TLP classification and first/last-seen dates are estimated locally "
    "(randomly assigned/jittered) for display purposes — they are not part "
    "of the original IOC from the source feed. Only type, value, malware, "
    "confidence and source come from the real indicator."
)
IOC_ESTIMATED_NOTE_AR = (
    "تصنيف TLP وتواريخ أول/آخر ظهور مُقدَّرة محلياً (مُعيَّنة/مُهتزة عشوائياً) لأغراض "
    "العرض فقط، وليست جزءاً من بيانات IOC الأصلية من مصدر التغذية. الحقول الحقيقية "
    "فقط هي: النوع والقيمة والبرمجية الخبيثة ومستوى الثقة والمصدر."
)

# get_threat_map() now plots real geolocated IP IOCs from the local `iocs`
# table (see _geolocate_ips() below) — this note explains the map's actual
# methodology/limits to the UI instead of disclosing fabrication.
MAP_METHOD_NOTE_EN = (
    "Points are real IP indicators from the local threat database, "
    "geolocated via ip-api.com/ipinfo.io and grouped by country. The count "
    "shown is the number of distinct known-malicious indicators from that "
    "country currently in the database — not a real-time attack rate. "
    "Countries with no geolocated IP indicators are not shown."
)
MAP_METHOD_NOTE_AR = (
    "النقاط هي مؤشرات IP حقيقية من قاعدة بيانات التهديدات المحلية، مُحدَّدة "
    "الموقع عبر ip-api.com/ipinfo.io ومجمَّعة حسب الدولة. العدد المعروض هو عدد "
    "المؤشرات الخبيثة المعروفة فعلياً من تلك الدولة في القاعدة حالياً — وليس "
    "معدل هجمات لحظي. الدول بلا مؤشرات IP محدَّدة الموقع لا تُعرض."
)

# Every IOC below is tagged is_sample=True/False per FEED_SOURCES/provenance —
# see get_live_ioc_feed(). Only URLhaus-sourced IOCs are is_sample=False.
SAMPLE_DATA_NOTE_EN = (
    "This indicator is fabricated sample/demo data shown under the named "
    "source's label for UI illustration — it is not a live feed from that "
    "source. Only URLhaus-sourced indicators in this feed are live."
)
SAMPLE_DATA_NOTE_AR = (
    "هذا المؤشر بيانات تجريبية/توضيحية مُلصقة باسم المصدر المذكور لغرض العرض "
    "فقط، وليست تغذية حية من ذلك المصدر. المؤشرات القادمة من URLhaus فقط هي "
    "الحية في هذه التغذية."
)

# ── Threat Map / Campaigns — now built from real data, see get_threat_map()
# and get_campaigns() below. The hardcoded THREAT_MAP_POINTS (20 countries
# with fabricated attacks_per_hour) and ATTACK_CAMPAIGNS (4 invented APT
# campaigns with made-up 78-94% confidence) that used to live here are gone:
# get_threat_map() now geolocates real IP IOCs from the local `iocs` table
# via modules/osint/geo_intel.py, and get_campaigns() now reads real OTX
# pulses via otx_feed.fetch_otx_pulse_campaigns(). Neither has a static
# fallback table — an unconfigured/empty source means an honest empty
# result, not fabricated data.


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

    # Merge static + stored + real URLhaus IOCs, tagging provenance up front:
    # _SAMPLE_IOCS entries are fabricated (is_sample=True); urlhaus_iocs are
    # real synced indicators (is_sample=False); shared_iocs are real
    # user submissions via submit_ioc() (is_sample=False, or whatever it was
    # stamped with — submit_ioc() always stamps False).
    all_iocs = (
        [{**ioc, "is_sample": True} for ioc in _SAMPLE_IOCS]
        + [{**ioc, "is_sample": False} for ioc in (urlhaus_iocs or [])]
    )
    for stored in data.get("shared_iocs", [])[:20]:
        all_iocs.insert(0, {"is_sample": False, **stored})

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
            # tlp/first_seen/last_seen just above are randomly generated, not
            # sourced from the original IOC — see IOC_ESTIMATED_NOTE_EN/AR.
            "tlp_source": "estimated",
            "date_source": "estimated",
            "note": IOC_ESTIMATED_NOTE_EN,
            "note_ar": IOC_ESTIMATED_NOTE_AR,
            # is_sample (carried over from the merge above) marks whether
            # this specific indicator is fabricated demo data — see
            # SAMPLE_DATA_NOTE_EN/AR.
            "sample_note": SAMPLE_DATA_NOTE_EN if ioc.get("is_sample") else None,
            "sample_note_ar": SAMPLE_DATA_NOTE_AR if ioc.get("is_sample") else None,
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


# `ioc["malware"]` traces to free text a third party attached to the IOC (a
# URLhaus reporter's tag, an OTX pulse's malware_families label — see
# modules/threat_intel/urlhaus_feed.py / otx_feed.py). The original checks
# below (`any(apt in malware for apt in [...])`, `"apt" in malware.lower()`)
# were a *substring* match, so any tag merely containing those letters
# (e.g. "adapter" contains "apt") got mislabeled nation-state — same bug
# class as the OTX `adversary` incident (modules/threat_intel/actor_naming.py).
#
# This is deliberately a small curated allowlist rather than
# actor_naming.looks_like_threat_actor_name(): that heuristic's
# single-capitalized-word fallback is correct for a field whose whole
# purpose is attribution (OTX's `adversary`), but a malware *family* name
# being one capitalized word is the norm, not the exception (Mirai, Ryuk,
# Emotet, Conti, LockBit, ...) — reusing it here would trade one false
# positive for a much larger one.
_NATION_STATE_MALWARE_LABELS = {"apt", "lazarus", "lazarus group", "sandworm", "hafnium"}
_RE_APT_CODE = re.compile(r"^apt[\s-]?\d{1,4}$", re.I)


def _is_nation_state_malware_label(malware: str) -> bool:
    label = (malware or "").strip().lower()
    return bool(label) and (label in _NATION_STATE_MALWARE_LABELS or bool(_RE_APT_CODE.match(label)))


def _aggregate_threat_score(ioc: dict) -> int:
    base = ioc.get("confidence", 50)
    source = next((s for s in FEED_SOURCES if s["id"] == ioc.get("source", "")), None)
    reliability = source["reliability"] if source else 0.7
    multiplier = 1.2 if _is_nation_state_malware_label(ioc.get("malware", "")) else 1.0
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
    # Same fix as _aggregate_threat_score() above — see its comment.
    if _is_nation_state_malware_label(ioc.get("malware", "")):
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


_VALID_IOC_TYPES = {"ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "email", "cve"}
_VALID_TLP = {"WHITE", "GREEN", "AMBER", "RED"}
_MAX_IOC_VALUE_LEN = 300
_MAX_IOC_MALWARE_LEN = 100


def submit_ioc(
    ioc_type: str, value: str, malware: str, confidence: int, tlp: str = "AMBER",
    user_id: Optional[int] = None,
) -> dict:
    """Submit a new IOC to the shared feed.

    This feed is rendered to every account with the threat_feed
    entitlement (GET /api/feed), so a submission is effectively public
    within the platform -- type/tlp are restricted to known enums, value/
    malware are length-capped, and every submission is stamped with
    user_id so an abusive one can be traced back to the account that sent
    it (the response never included that stamp before this fix).
    """
    ioc_type = (ioc_type or "").strip().lower()
    if ioc_type not in _VALID_IOC_TYPES:
        raise ValueError(f"ioc_type must be one of: {', '.join(sorted(_VALID_IOC_TYPES))}")
    value = (value or "").strip()[:_MAX_IOC_VALUE_LEN]
    if not value:
        raise ValueError("value is required")
    malware = (malware or "unknown").strip()[:_MAX_IOC_MALWARE_LEN]
    tlp = (tlp or "AMBER").strip().upper()
    if tlp not in _VALID_TLP:
        tlp = "AMBER"

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
        "submitted_by": user_id,
        # Real data entered by a real user, not fabricated demo data — see
        # SAMPLE_DATA_NOTE_EN/AR and get_live_ioc_feed()'s provenance tagging.
        "is_sample": False,
    }
    data["shared_iocs"].insert(0, ioc)
    data["shared_iocs"] = data["shared_iocs"][:200]
    data["feed_stats"]["total_iocs"] = data["feed_stats"].get("total_iocs", 0) + 1
    data["feed_stats"]["shared_today"] = data["feed_stats"].get("shared_today", 0) + 1
    _save_data(data)
    return ioc


async def _geolocate_ips(ips: List[str]) -> Dict[str, dict]:
    """Geolocate real IPs via modules.osint.geo_intel (ip-api.com, with an
    ipinfo.io fallback — neither requires an API key), backed by a local
    TTL file cache so repeat Threat Map loads don't re-hit the geolocation
    service for IPs already resolved recently. An IP that fails to
    geolocate (both providers down/rate-limited) is simply absent from the
    result — never given a guessed or interpolated location."""
    cache: dict = {}
    if GEO_CACHE_FILE.exists():
        try:
            cache = json.loads(GEO_CACHE_FILE.read_text())
        except Exception:
            cache = {}

    now = time.time()
    result: Dict[str, dict] = {}
    to_fetch = []
    for ip in ips:
        entry = cache.get(ip)
        if entry and now - entry.get("_cached_at", 0) < GEO_CACHE_TTL:
            result[ip] = entry
        else:
            to_fetch.append(ip)

    if to_fetch:
        from modules.osint.geo_intel import geolocate_ip

        fetched = await asyncio.gather(*(geolocate_ip(ip) for ip in to_fetch), return_exceptions=True)
        for ip, geo in zip(to_fetch, fetched):
            if isinstance(geo, Exception) or not isinstance(geo, dict) or geo.get("error"):
                continue
            if geo.get("lat") is None or geo.get("lon") is None:
                continue
            entry = {
                "lat": geo["lat"],
                "lon": geo["lon"],
                "country": geo.get("country") or "Unknown",
                "country_code": geo.get("country_code") or "??",
                "_cached_at": now,
            }
            cache[ip] = entry
            result[ip] = entry

    try:
        GEO_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        GEO_CACHE_FILE.write_text(json.dumps(cache))
    except Exception:
        logger.warning("failed to persist threat-map geo cache", exc_info=True)

    return result


async def get_threat_map(db: "AsyncSession") -> dict:
    """Threat map built from real geolocated IP indicators in the local
    `iocs` table (web.models.Ioc, populated by modules/ioc/scheduler.py's
    OTX/URLhaus sync) — see MAP_METHOD_NOTE_EN/AR for exactly what each
    field means. Returns an empty `points` list, not a guessed one, when
    no IP IOCs are active yet (e.g. feeds never synced)."""
    from modules.ioc.ioc_engine import IOCRepository

    repo = IOCRepository(db)
    rows = await repo.list_active(ioc_type="ip", limit=200)
    ips = sorted({row.ioc_value for row in rows})

    if not ips:
        return {
            "points": [],
            "total_known_malicious_ips": 0,
            "updated_at": datetime.utcnow().isoformat(),
            "top_origin": None,
            "note": MAP_METHOD_NOTE_EN,
            "note_ar": MAP_METHOD_NOTE_AR,
        }

    geo = await _geolocate_ips(ips)

    by_country: Dict[str, dict] = {}
    for row in rows:
        g = geo.get(row.ioc_value)
        if not g:
            continue  # couldn't geolocate this one — omitted, not guessed
        bucket = by_country.setdefault(g["country_code"], {
            "country": g["country"], "code": g["country_code"],
            "lat_sum": 0.0, "lon_sum": 0.0, "n": 0, "known_malicious_ioc_count": 0,
        })
        bucket["lat_sum"] += g["lat"]
        bucket["lon_sum"] += g["lon"]
        bucket["n"] += 1
        bucket["known_malicious_ioc_count"] += 1

    points = []
    for bucket in by_country.values():
        n = bucket["n"]
        count = bucket["known_malicious_ioc_count"]
        # Display-only bucketing of the real count above (not a threat
        # assessment) so the UI can color-code markers.
        density_tier = "high" if count >= 10 else "medium" if count >= 3 else "low"
        points.append({
            "country": bucket["country"],
            "code": bucket["code"],
            "lat": round(bucket["lat_sum"] / n, 4),
            "lon": round(bucket["lon_sum"] / n, 4),
            "known_malicious_ioc_count": count,
            "density_tier": density_tier,
        })
    points.sort(key=lambda p: p["known_malicious_ioc_count"], reverse=True)

    return {
        "points": points,
        "total_known_malicious_ips": len(ips),
        "updated_at": datetime.utcnow().isoformat(),
        "top_origin": points[0]["country"] if points else None,
        "note": MAP_METHOD_NOTE_EN,
        "note_ar": MAP_METHOD_NOTE_AR,
    }


CAMPAIGNS_UNAVAILABLE_NOTE_EN = "OTX_API_KEY is not configured — no live campaign data available."
CAMPAIGNS_UNAVAILABLE_NOTE_AR = "لم يتم ضبط OTX_API_KEY — لا تتوفر بيانات حملات حية."


async def get_campaigns(api_key: str) -> dict:
    """Live AlienVault OTX pulses, presented as campaign-like entries — see
    otx_feed.fetch_otx_pulse_campaigns() for exactly which fields are real
    (name, actor when verified, dates, sectors, countries, MITRE technique
    IDs, IOC count) versus deliberately omitted (there is no "confidence"
    field — OTX has no such concept for a pulse, so none is invented here).
    No local fallback table: an unconfigured key or an OTX outage returns
    an empty, clearly-labeled result, never a stand-in fabricated campaign.
    """
    if not api_key:
        return {
            "campaigns": [], "otx_connected": False,
            "note": CAMPAIGNS_UNAVAILABLE_NOTE_EN, "note_ar": CAMPAIGNS_UNAVAILABLE_NOTE_AR,
        }
    from modules.threat_intel.otx_feed import fetch_otx_pulse_campaigns

    try:
        campaigns = await asyncio.to_thread(fetch_otx_pulse_campaigns, api_key, 20)
    except Exception as exc:
        logger.warning("OTX pulse-campaign fetch failed: %s", exc)
        return {
            "campaigns": [], "otx_connected": False,
            "note": f"OTX fetch failed: {exc}",
            "note_ar": f"فشل جلب بيانات OTX: {exc}",
        }
    return {"campaigns": campaigns, "otx_connected": True, "note": None, "note_ar": None}


TTP_REFERENCE_NOTE_EN = (
    "General MITRE ATT&CK technique associations by indicator type "
    "(e.g. IP indicators commonly relate to T1071/T1090) — a reference "
    "list, not an analysis finding derived from these specific IOCs."
)
TTP_REFERENCE_NOTE_AR = (
    "ارتباطات عامة بتقنيات MITRE ATT&CK حسب نوع المؤشر (مثال: مؤشرات IP ترتبط "
    "عادة بـT1071/T1090) — قائمة مرجعية عامة، وليست نتيجة تحليل مستخلصة من هذه "
    "المؤشرات تحديداً."
)


async def correlate_iocs(ioc_list: List[dict], db: "AsyncSession") -> dict:
    """Correlate submitted IOCs against indicators this platform actually
    knows about (the local `iocs` table — real OTX/URLhaus-synced data,
    see web.models.Ioc) and against each other's real structural overlap
    (shared /24 subnet, a URL hosted on a submitted domain). Replaces the
    old version, which matched against four hardcoded fictional APT
    campaigns and returned an invented 78-94%-range "confidence" —  see
    CAMPAIGNS_UNAVAILABLE_NOTE_EN and this function's git history. There is
    no campaign attribution here any more: a match only ever reports real
    evidence (which local record, from which source, since when), and
    `match_rate` is a real ratio (matched / submitted), not a confidence
    score standing in for one.
    """
    from modules.ioc.ioc_engine import IOCRepository
    from modules.ioc_correlation import _ip_subnet, _extract_domain_from_url

    repo = IOCRepository(db)
    known_matches = []
    for ioc in ioc_list:
        ioc_type = (ioc.get("type") or "").strip().lower()
        value = (ioc.get("value") or "").strip()
        if not ioc_type or not value:
            continue
        row = await repo.get_by_value(ioc_type, value)
        if row is None:
            continue
        pulses = [t[len("pulse:"):] for t in (row.tags or []) if t.startswith("pulse:")]
        known_matches.append({
            "ioc": ioc,
            "source": row.source,
            "confidence_score": row.confidence_score,
            "first_seen": row.first_seen.isoformat() if row.first_seen else None,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            "pulses": pulses,
            "tags": row.tags or [],
        })

    # Structural relationships between the *submitted* IOCs themselves —
    # deterministic, same helpers modules/ioc_correlation.py uses for its
    # own clustering (not duplicated here).
    relationships = []
    subnet_map: Dict[str, List[str]] = {}
    submitted_domains = {i.get("value", "").lower() for i in ioc_list if i.get("type") == "domain"}
    for ioc in ioc_list:
        t = (ioc.get("type") or "").lower()
        value = ioc.get("value", "")
        if t == "ip":
            subnet = _ip_subnet(value)
            if subnet:
                subnet_map.setdefault(subnet, []).append(value)
        elif t == "url":
            d = _extract_domain_from_url(value)
            if d and d in submitted_domains:
                relationships.append({"type": "hosted_on", "url": value, "domain": d})
    for subnet, members in subnet_map.items():
        if len(members) >= 2:
            relationships.append({"type": "shared_subnet", "subnet": subnet, "values": members})

    ip_count = sum(1 for i in ioc_list if i.get("type") == "ip")
    domain_count = sum(1 for i in ioc_list if i.get("type") == "domain")
    hash_count = sum(1 for i in ioc_list if "hash" in (i.get("type") or ""))

    return {
        "submitted_count": len(ioc_list),
        "known_matches": known_matches,
        "match_rate": round((len(known_matches) / max(len(ioc_list), 1)) * 100, 1),
        "match_rate_note": (
            "Share of submitted IOCs that exactly match a real indicator "
            "already in this platform's local threat database — not an "
            "attribution or confidence score."
        ),
        "relationships": relationships,
        "pattern_analysis": {
            "ip_indicators": ip_count,
            "domain_indicators": domain_count,
            "file_indicators": hash_count,
            "indicator_type_ttp_reference": _infer_ttps(ioc_list),
            "ttp_reference_note": TTP_REFERENCE_NOTE_EN,
            "ttp_reference_note_ar": TTP_REFERENCE_NOTE_AR,
        },
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
        "sample_ioc_count": len(_SAMPLE_IOCS),
        "shared_ioc_count": len(data.get("shared_iocs", [])),
        "updated_at": datetime.utcnow().isoformat(),
    }
