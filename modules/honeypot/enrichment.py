"""
Honeypot attacker IP enrichment — geolocation + AbuseIPDB reputation.

Every connection captured by modules/honeypot/listeners.py is enriched here
before it's persisted, per the roadmap item "ربط IP المهاجم تلقائياً
بمصادر التهديد الموجودة (AbuseIPDB) لإثراء المعلومة (geolocation, reputation
score)":
  - Geolocation reuses modules.osint.geo_intel.geolocate_ip (ip-api.com +
    ipinfo.io) — the same provider already used for target geolocation
    elsewhere in the project, so no new provider/key is introduced.
  - Reputation queries AbuseIPDB directly via the same ABUSEIPDB_API_KEY env
    var already used by modules/threat_intel/ioc_detector.py and
    modules/threat_intel/honeypot.py — kept in sync deliberately.

Never raises: a honeypot hit must always be stored even when every
enrichment provider is unreachable or unset, so every lookup here degrades
to safe defaults instead of propagating an exception.
"""
from __future__ import annotations

import asyncio
import os

import httpx

from modules.osint.geo_intel import geolocate_ip

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

RISK_LEVELS_AR: dict[str, str] = {
    "LOW": "منخفض",
    "MEDIUM": "متوسط",
    "HIGH": "مرتفع",
    "CRITICAL": "حرج",
    "UNKNOWN": "غير معروف",
}


async def _query_abuseipdb(ip: str) -> dict:
    """Check `ip` against AbuseIPDB. Returns
    {available, score, total_reports, is_tor, usage_type, domain, error}.
    Never raises."""
    empty = {
        "available": False, "score": 0, "total_reports": 0, "is_tor": False,
        "usage_type": None, "domain": None, "error": None,
    }
    if not ABUSEIPDB_KEY:
        return {**empty, "error": "ABUSEIPDB_API_KEY not set"}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                ABUSEIPDB_URL,
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
    except Exception as exc:
        return {**empty, "error": str(exc)}

    return {
        "available": True,
        "score": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
        "is_tor": data.get("isTor", False),
        "usage_type": data.get("usageType"),
        "domain": data.get("domain"),
        "error": None,
    }


def _risk_level(abuse_score: int, geo_risk_score: int) -> str:
    combined = max(abuse_score or 0, geo_risk_score or 0)
    if combined >= 75:
        return "CRITICAL"
    if combined >= 50:
        return "HIGH"
    if combined >= 25:
        return "MEDIUM"
    return "LOW"


async def enrich_ip(ip: str) -> dict:
    """Enrich a honeypot attacker IP with geolocation + AbuseIPDB reputation.

    Returns a flat dict ready to denormalize onto a HoneypotEvent row, plus
    the raw `geo`/`abuse` sub-results for the full JSON `enrichment` column.
    Never raises.
    """
    geo, abuse = await asyncio.gather(
        geolocate_ip(ip), _query_abuseipdb(ip), return_exceptions=True,
    )

    if isinstance(geo, Exception) or not isinstance(geo, dict) or geo.get("error"):
        geo = {"country": None, "country_code": None, "city": None, "isp": None,
                "asn": None, "risk_score": 0, "error": geo.get("error") if isinstance(geo, dict) else str(geo)}
    if isinstance(abuse, Exception):
        abuse = {"available": False, "score": 0, "total_reports": 0, "is_tor": False,
                  "usage_type": None, "domain": None, "error": str(abuse)}

    risk_level = _risk_level(abuse.get("score", 0), geo.get("risk_score", 0))

    return {
        "ip": ip,
        "country": geo.get("country"),
        "country_code": geo.get("country_code"),
        "city": geo.get("city"),
        "isp": geo.get("isp"),
        "asn": geo.get("asn"),
        "abuse_score": abuse.get("score", 0),
        "abuse_reports": abuse.get("total_reports", 0),
        "is_tor": abuse.get("is_tor", False),
        "risk_level": risk_level,
        "risk_level_ar": RISK_LEVELS_AR.get(risk_level, risk_level),
        "geo": geo,
        "abuse": abuse,
    }
