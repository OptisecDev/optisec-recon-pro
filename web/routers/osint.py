"""OSINT Router — world-class open-source intelligence engine."""

import asyncio
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import get_db
from web.models import User
from web.auth import get_current_user
from web.shared_templates import templates
from config import APP_NAME

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
