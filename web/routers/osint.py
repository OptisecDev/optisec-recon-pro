"""OSINT Router — world-class open-source intelligence engine."""

import asyncio
import logging
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import get_db
from web.models import User
from web.auth import get_current_user
from web.shared_templates import templates
from config import APP_NAME

logger = logging.getLogger("osint.router")
router = APIRouter(tags=["osint"])


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


# ── Phone Number Intelligence ──────────────────────────────────────────────────

@router.post("/api/osint/phone")
async def osint_phone(request: Request, user: User = Depends(_user)):
    data = await request.json()
    number = data.get("number", "").strip()
    if not number:
        raise HTTPException(400, "Phone number is required")

    from modules.osint.phone_intel import analyze_phone
    result = await asyncio.to_thread(analyze_phone, number)
    return JSONResponse(result)


# ── Username / Social Footprint ────────────────────────────────────────────────

@router.post("/api/osint/username")
async def osint_username(request: Request, user: User = Depends(_user)):
    data = await request.json()
    username = data.get("username", "").strip()
    if not username or len(username) < 2:
        raise HTTPException(400, "Username must be at least 2 characters")

    from modules.osint.username_footprint import search_username
    result = await search_username(username)
    return JSONResponse(result)


# ── Device Fingerprinting ──────────────────────────────────────────────────────

@router.post("/api/osint/device")
async def osint_device(request: Request, user: User = Depends(_user)):
    data = await request.json()
    ua = data.get("user_agent", "").strip()
    if not ua:
        # Auto-detect from request header
        ua = request.headers.get("user-agent", "")
    if not ua:
        raise HTTPException(400, "User-Agent string is required")

    from modules.osint.device_fingerprint import fingerprint_device
    result = await asyncio.to_thread(fingerprint_device, ua)
    return JSONResponse(result)


# ── Vehicle Plate Intelligence ─────────────────────────────────────────────────

@router.post("/api/osint/plate")
async def osint_plate(request: Request, user: User = Depends(_user)):
    data = await request.json()
    plate = data.get("plate", "").strip()
    if not plate:
        raise HTTPException(400, "Plate number is required")

    from modules.osint.vehicle_plate import decode_plate
    result = await asyncio.to_thread(decode_plate, plate)
    return JSONResponse(result)


@router.get("/api/osint/plate/provinces")
async def osint_provinces(user: User = Depends(_user)):
    from modules.osint.vehicle_plate import list_provinces
    return JSONResponse({"provinces": list_provinces()})


# ── Geographic Intelligence ────────────────────────────────────────────────────

@router.post("/api/osint/ip")
async def osint_ip(request: Request, user: User = Depends(_user)):
    data = await request.json()
    target = data.get("target", "").strip()
    if not target:
        raise HTTPException(400, "IP address or domain is required")

    from modules.osint.geo_intel import geolocate_ip
    result = await geolocate_ip(target)
    return JSONResponse(result)


# ── Cell Tower Fingerprinting ──────────────────────────────────────────────────

@router.post("/api/osint/cell")
async def osint_cell(request: Request, user: User = Depends(_user)):
    data = await request.json()
    try:
        mcc = int(data.get("mcc", 0))
        mnc = int(data.get("mnc", 0))
    except (ValueError, TypeError):
        raise HTTPException(400, "MCC and MNC must be integers")

    if not mcc or not mnc:
        raise HTTPException(400, "MCC and MNC are required")

    lac = data.get("lac")
    cell_id = data.get("cell_id")
    signal_dbm = data.get("signal_dbm")

    try:
        if lac is not None:
            lac = int(lac)
        if cell_id is not None:
            cell_id = int(cell_id)
        if signal_dbm is not None:
            signal_dbm = int(signal_dbm)
    except (ValueError, TypeError):
        pass

    from modules.osint.cell_tower import lookup_cell_tower
    result = await asyncio.to_thread(lookup_cell_tower, mcc, mnc, lac, cell_id, signal_dbm)
    return JSONResponse(result)


@router.get("/api/osint/cell/iraq-carriers")
async def osint_iraq_carriers(user: User = Depends(_user)):
    from modules.osint.cell_tower import list_iraq_carriers
    return JSONResponse({"carriers": list_iraq_carriers()})


# ── National ID Intelligence ───────────────────────────────────────────────────

@router.post("/api/osint/national-id")
async def osint_national_id(request: Request, user: User = Depends(_user)):
    data = await request.json()
    nid = data.get("id", "").strip()
    if not nid:
        raise HTTPException(400, "National ID is required")

    from modules.osint.national_id import analyze_national_id
    result = await asyncio.to_thread(analyze_national_id, nid)
    return JSONResponse(result)


# ── Phone → Social Accounts OSINT ─────────────────────────────────────────────

@router.post("/api/osint/phone-social")
async def osint_phone_social(request: Request, user: User = Depends(_user)):
    data = await request.json()
    number = data.get("number", "").strip()
    if not number:
        raise HTTPException(400, "Phone number is required")

    from modules.osint.phone_social import phone_social_lookup
    result = await phone_social_lookup(number)
    return JSONResponse(result)


# ── Full Domain OSINT (existing enhanced) ─────────────────────────────────────

@router.post("/api/osint/domain")
async def osint_domain(request: Request, user: User = Depends(_user)):
    data = await request.json()
    domain = data.get("domain", "").strip()
    if not domain:
        raise HTTPException(400, "Domain is required")

    from modules.osint.email_finder import find_emails
    from modules.osint.social_media import find_social_profiles
    from modules.recon.dns_lookup import dns_lookup
    from modules.recon.whois_lookup import whois_lookup
    from modules.recon.subdomains import enumerate_subdomains
    from modules.osint.geo_intel import geolocate_ip

    emails_t = asyncio.to_thread(find_emails, domain)
    social_t = asyncio.to_thread(find_social_profiles, domain)
    dns_t = asyncio.to_thread(dns_lookup, domain)
    whois_t = asyncio.to_thread(whois_lookup, domain)
    subs_t = asyncio.to_thread(enumerate_subdomains, domain)
    geo_t = geolocate_ip(domain)

    results = await asyncio.gather(
        emails_t, social_t, dns_t, whois_t, subs_t, geo_t,
        return_exceptions=True,
    )
    emails, social, dns_data, whois_data, subs, geo = results

    return JSONResponse({
        "domain": domain,
        "emails": emails if not isinstance(emails, Exception) else {"error": str(emails)},
        "social": social if not isinstance(social, Exception) else {"error": str(social)},
        "dns": dns_data if not isinstance(dns_data, Exception) else {"error": str(dns_data)},
        "whois": whois_data if not isinstance(whois_data, Exception) else {"error": str(whois_data)},
        "subdomains": subs if not isinstance(subs, Exception) else [],
        "geolocation": geo if not isinstance(geo, Exception) else {"error": str(geo)},
    })


# ── Unified OSINT Engine v5.0 ─────────────────────────────────────────────────

_VALID_TARGET_TYPES = {"domain", "email", "username", "ip", "auto"}

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_SEVERITY_RANK = {sev: i for i, sev in enumerate(_SEVERITY_ORDER)}
_SEVERITY_AR = {
    "critical": "حرجة",
    "high": "عالية",
    "medium": "متوسطة",
    "low": "منخفضة",
    "info": "معلوماتية",
}
_TYPE_AR = {
    "subdomain": "نطاق فرعي",
    "email": "بريد إلكتروني",
    "account": "حساب مسجل",
    "profile": "ملف شخصي عام",
    "whois_record": "بيانات تسجيل النطاق (WHOIS)",
    "dmarc_status": "سجل DMARC",
    "spf_status": "سجل SPF",
    "dns_record": "سجل DNS",
}
_TYPE_EN = {
    "subdomain": "subdomain",
    "email": "email address",
    "account": "registered account",
    "profile": "public profile",
    "whois_record": "domain registration (WHOIS) record",
    "dmarc_status": "DMARC record",
    "spf_status": "SPF record",
    "dns_record": "DNS record",
}


def _build_executive_summary(entities: list[dict], target: str) -> dict[str, str]:
    """
    One-sentence Arabic + English summary of the most security-relevant
    finding, for a non-technical reader skimming the top of the report.

    Picks the single highest-severity entity (critical > high > ... > info)
    and names it; if nothing rises above low/info, says so explicitly
    rather than manufacturing urgency.
    """
    if not entities:
        return {
            "ar": f"لم يتم العثور على أي نتائج لـ {target}.",
            "en": f"No findings were discovered for {target}.",
        }

    worst = min(entities, key=lambda e: _SEVERITY_RANK.get(e.get("severity"), 4))
    worst_rank = _SEVERITY_RANK.get(worst.get("severity"), 4)

    if worst_rank >= _SEVERITY_RANK["low"]:
        return {
            "ar": f"تم تحليل {len(entities)} كيان لـ {target} دون رصد مخاطر عالية أو حرجة.",
            "en": f"Analyzed {len(entities)} entities for {target} with no high or critical risks detected.",
        }

    severity_ar = _SEVERITY_AR.get(worst.get("severity"), worst.get("severity", ""))
    type_ar = _TYPE_AR.get(worst.get("type"), worst.get("type") or "نتيجة")
    severity_en = worst.get("severity", "")
    type_en = _TYPE_EN.get(worst.get("type"), worst.get("type") or "finding")
    return {
        "ar": (
            f"تم رصد {len(entities)} كيان لـ {target}، أبرزها {type_ar} "
            f"بخطورة {severity_ar} ({worst.get('value', '')})."
        ),
        "en": (
            f"Detected {len(entities)} entities for {target}; most notably a "
            f"{severity_en}-severity {type_en} ({worst.get('value', '')})."
        ),
    }


@router.post(
    "/api/osint/unified-search",
    summary="Unified OSINT Engine v5.0",
    description=(
        "Run all applicable OSINT sources in parallel: "
        "**Amass**, **crt.sh**, **Wayback Machine**, full **DNS**, and "
        "**WHOIS** (subdomain/registration intel), "
        "**theHarvester** (emails/hosts), "
        "**Maigret** (username across 500+ sites), "
        "**Holehe** (email account checker). "
        "Sources are dispatched based on `target_type`. "
        "Use `auto` to let the engine detect the type automatically. "
        "Each source runs with an independent timeout so a slow/failing "
        "one never blocks the others.\n\n"
        "Results are deduplicated/correlated across sources and scored for "
        "confidence and severity before being returned as `entities`; the "
        "untouched per-source output is still available under "
        "`raw_sources` for advanced users. `summary.executive_summary` "
        "carries a one-line verdict in both Arabic (`ar`) and English "
        "(`en`).\n\n"
        "**Note:** Amass/theHarvester/Maigret/Holehe require their binaries "
        "to be installed separately (`pip install theHarvester maigret "
        "holehe`); crt.sh/Wayback/DNS/WHOIS need no installation."
    ),
)
async def osint_unified_search(request: Request, user: User = Depends(_user)):
    data = await request.json()
    target = data.get("target", "").strip()
    target_type = data.get("target_type", "auto").strip().lower()

    if not target:
        raise HTTPException(400, "target is required")
    if target_type not in _VALID_TARGET_TYPES:
        raise HTTPException(
            400,
            f"target_type must be one of: {', '.join(sorted(_VALID_TARGET_TYPES))}",
        )

    logger.info(
        "unified_search request user=%s target=%r type=%s ip=%s",
        user.username, target, target_type,
        request.client.host if request.client else "unknown",
    )

    from modules.osint.unified_engine import search_unified
    from modules.osint.confidence_engine import calculate_confidence, classify_severity
    from modules.osint.correlation_engine import build_entity_graph

    raw_result = await search_unified(target, target_type, rate_key=f"user:{user.id}")

    if raw_result.get("error") == "rate_limited":
        raise HTTPException(429, raw_result.get("message", "Rate limit exceeded"))

    raw_sources = raw_result.get("sources", [])
    entity_graph = build_entity_graph(raw_sources)

    severity_breakdown = dict.fromkeys(_SEVERITY_ORDER, 0)
    entities: list[dict] = []
    for entity in entity_graph.values():
        entity["confidence"] = calculate_confidence(entity, raw_sources)
        severity = classify_severity(entity)
        entity["severity"] = severity
        severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1
        entities.append(entity)

    entities.sort(key=lambda e: (_SEVERITY_RANK.get(e["severity"], 4), -e["confidence"]))

    return JSONResponse({
        "target": raw_result["target"],
        "target_type": raw_result["target_type"],
        "elapsed_seconds": raw_result["elapsed_seconds"],
        "summary": {
            "total_findings": raw_result.get("total_results", 0),
            "unique_entities": len(entities),
            "severity_breakdown": severity_breakdown,
            "executive_summary": _build_executive_summary(entities, target),
        },
        "entities": entities,
        "raw_sources": raw_sources,
    })


@router.post(
    "/api/osint/network-scan",
    summary="Advanced Network Intelligence — Phase 2A",
    description=(
        "Passive Shodan/Censys/BGP/SSL recon on a target IP or domain, "
        "scored into a 0-100 attack-surface rating. Shodan falls back to "
        "the free, keyless Shodan InternetDB if `SHODAN_API_KEY` isn't "
        "configured; Censys is skipped unless both `CENSYS_API_ID` and "
        "`CENSYS_API_SECRET` are set. Set `deep_scan: true` to also "
        "actively banner-grab the ports Shodan/Censys reported open — "
        "only do this against hosts you are authorized to test."
    ),
)
async def osint_network_scan(request: Request, user: User = Depends(_user)):
    data = await request.json()
    target = data.get("target", "").strip()
    deep_scan = bool(data.get("deep_scan", False))
    if not target:
        raise HTTPException(400, "target is required")

    logger.info(
        "network_scan request user=%s target=%r deep_scan=%s ip=%s",
        user.username, target, deep_scan,
        request.client.host if request.client else "unknown",
    )

    from modules.osint.network_intelligence import gather_network_intelligence
    result = await gather_network_intelligence(target, deep_scan=deep_scan)
    return JSONResponse(result)


@router.post(
    "/api/osint/darkweb-scan",
    summary="Dark Web & Breach Intelligence — Phase 2B",
    description=(
        "Breach/leak/threat-actor exposure scan via official APIs and free "
        "legal indexes only — **never** dark web scraping. Queries HIBP, "
        "IntelligenceX, BreachDirectory, Leak-Lookup, psbdmp.ws, GitHub "
        "Code Search and AlienVault OTX. Most sources are optional and "
        "require their own key (`HIBP_API_KEY`, `INTELX_API_KEY`, "
        "`RAPIDAPI_KEY`, `LEAKLOOKUP_API_KEY`, `GITHUB_TOKEN`, "
        "`OTX_API_KEY`); an unconfigured source degrades to "
        "`available: false` rather than failing the whole scan. "
        "`target` may be an email or a domain — set `include_pastes`/"
        "`include_github` to false to skip those sources."
    ),
)
async def osint_darkweb_scan(request: Request, user: User = Depends(_user)):
    data = await request.json()
    target = data.get("target", "").strip()
    if not target:
        raise HTTPException(400, "target is required")
    include_pastes = bool(data.get("include_pastes", True))
    include_github = bool(data.get("include_github", True))

    logger.info(
        "darkweb_scan request user=%s target=%r include_pastes=%s include_github=%s ip=%s",
        user.username, target, include_pastes, include_github,
        request.client.host if request.client else "unknown",
    )

    from modules.osint.darkweb_intelligence import gather_darkweb_intelligence
    result = await gather_darkweb_intelligence(target, include_pastes=include_pastes, include_github=include_github)
    exposure = result["exposure"]

    return JSONResponse({
        "target": result["target"],
        "target_type": result["target_type"],
        "breaches": result["breaches"],
        "pastes": result["pastes"],
        "github_exposures": result["github_exposures"],
        "threat_actors": result["threat_actors"],
        "darkweb_exposure_score": exposure["score"],
        "exposure_level": exposure["exposure_level"],
        "recommendations": exposure["recommendations"],
        "sources": {
            "intelx": result["intelx"],
            "breachdirectory": result["breachdirectory"],
            "leaklookup": result["leaklookup"],
            "threat_actor_detail": result["threat_actor_detail"],
        },
    })


@router.get(
    "/api/osint/sources-status",
    summary="OSINT source availability",
    description=(
        "Report every OSINT source's availability (binary installed / "
        "library reachable), whether it requires an API key, and when it "
        "was last invoked in this process — lets the UI show which "
        "sources will actually run before a search is launched."
    ),
)
async def osint_sources_status(user: User = Depends(_user)):
    from modules.osint.unified_engine import get_sources_status
    return JSONResponse({"sources": get_sources_status()})
