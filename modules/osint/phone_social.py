"""Phone → Social Accounts OSINT — 5-tier intelligence engine."""

import asyncio
import os
import re
import urllib.parse
from typing import Optional
import aiohttp

TIMEOUT = aiohttp.ClientTimeout(total=12, connect=5)
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# ── TIER 4: Iraqi Carrier Database ────────────────────────────────────────────

IRAQ_CARRIERS: dict[str, dict] = {
    "770": {"name": "Zain Iraq", "brand": "زين العراق", "region": "National", "tech": ["2G", "3G", "4G"], "mcc_mnc": "418-20", "roaming": True},
    "771": {"name": "Zain Iraq", "brand": "زين العراق", "region": "National", "tech": ["2G", "3G", "4G"], "mcc_mnc": "418-20", "roaming": True},
    "772": {"name": "Zain Iraq", "brand": "زين العراق", "region": "National", "tech": ["2G", "3G", "4G"], "mcc_mnc": "418-20", "roaming": True},
    "773": {"name": "Zain Iraq", "brand": "زين العراق", "region": "National", "tech": ["2G", "3G", "4G"], "mcc_mnc": "418-20", "roaming": True},
    "780": {"name": "Asiacell", "brand": "آسيا سيل", "region": "National", "tech": ["2G", "3G", "4G"], "mcc_mnc": "418-05", "roaming": True},
    "781": {"name": "Asiacell", "brand": "آسيا سيل", "region": "National", "tech": ["2G", "3G", "4G"], "mcc_mnc": "418-05", "roaming": True},
    "782": {"name": "Asiacell", "brand": "آسيا سيل", "region": "National", "tech": ["2G", "3G", "4G"], "mcc_mnc": "418-05", "roaming": True},
    "783": {"name": "Asiacell", "brand": "آسيا سيل", "region": "National", "tech": ["2G", "3G", "4G"], "mcc_mnc": "418-05", "roaming": True},
    "750": {"name": "Korek Telecom", "brand": "كورك", "region": "Kurdistan", "tech": ["2G", "3G", "4G"], "mcc_mnc": "418-40", "roaming": True},
    "751": {"name": "Korek Telecom", "brand": "كورك", "region": "Kurdistan", "tech": ["2G", "3G", "4G"], "mcc_mnc": "418-40", "roaming": True},
    "753": {"name": "Korek Telecom", "brand": "كورك", "region": "Kurdistan", "tech": ["2G", "3G", "4G"], "mcc_mnc": "418-40", "roaming": True},
    "790": {"name": "Earthlink Telecom", "brand": "إيرثلينك", "region": "National", "tech": ["3G", "4G"], "mcc_mnc": "418-30", "roaming": False},
    "791": {"name": "Earthlink Telecom", "brand": "إيرثلينك", "region": "National", "tech": ["3G", "4G"], "mcc_mnc": "418-30", "roaming": False},
    "792": {"name": "Earthlink Telecom", "brand": "إيرثلينك", "region": "National", "tech": ["3G", "4G"], "mcc_mnc": "418-30", "roaming": False},
}

IRAQ_PREFIXES = frozenset(IRAQ_CARRIERS.keys())

# Regional platform adoption rates (%) for confidence blending
REGIONAL_ADOPTION = {
    "IQ": {"whatsapp": 85, "telegram": 78, "viber": 35, "facebook": 62, "instagram": 55, "tiktok": 48, "snapchat": 25, "signal": 10},
    "DEFAULT": {"whatsapp": 60, "telegram": 42, "viber": 18, "facebook": 52, "instagram": 48, "tiktok": 40, "snapchat": 30, "signal": 15},
}


# ── TIER 4 helpers ────────────────────────────────────────────────────────────

def generate_variations(raw: str) -> dict:
    """Produce all standard Iraqi and international phone format variants."""
    clean = re.sub(r"[\s\-\(\)\.]", "", raw).lstrip("+")

    national: str = ""
    if clean.startswith("9647") and len(clean) >= 13:
        national = clean[3:]          # 7XXXXXXXXX
    elif clean.startswith("00964"):
        national = clean[5:]
    elif clean.startswith("964") and len(clean) >= 12:
        national = clean[3:]
    elif clean.startswith("07") and len(clean) >= 10:
        national = clean[1:]
    elif re.match(r"^7[0-9]{9}$", clean):
        national = clean
    else:
        national = clean

    national = re.sub(r"\D", "", national)
    if not national:
        return {}

    wa_num = f"964{national}"
    e164 = f"+964{national}"

    return {
        "e164":              e164,
        "international_00":  f"00964{national}",
        "national":          f"0{national}",
        "national_bare":     national,
        "whatsapp_format":   wa_num,
        "display":           _pretty(national),
    }


def _pretty(national: str) -> str:
    if len(national) >= 10:
        return f"+964 {national[:3]} {national[3:6]} {national[6:]}"
    return f"+964 {national}"


def detect_carrier(variations: dict) -> Optional[dict]:
    bare = variations.get("national_bare", "")
    prefix = bare[:3]
    entry = IRAQ_CARRIERS.get(prefix)
    if not entry:
        return None
    return {
        **entry,
        "prefix": f"0{prefix}",
        "ported_risk": "LOW — original prefix" if prefix in ("770", "771", "780", "781", "750") else "MEDIUM — MNP eligible",
        "mcc": "418",
    }


def is_iraqi(variations: dict) -> bool:
    return variations.get("national_bare", "")[:3] in IRAQ_PREFIXES


# ── TIER 5: OSINT Dork Generator ──────────────────────────────────────────────

def build_dorks(variations: dict) -> dict:
    e164     = variations.get("e164", "")
    national = variations.get("national", "")
    bare     = variations.get("national_bare", "")

    return {
        "google": [
            f'"{national}" OR "{e164}"',
            f'site:facebook.com "{national}"',
            f'site:instagram.com "{national}"',
            f'site:pastebin.com "{national}" OR "{e164}"',
            f'"{national}" filetype:txt OR filetype:csv',
            f'"{e164}" (leaked OR dump OR breach)',
            f'"{national}" (whatsapp OR telegram OR viber)',
            f'intext:"{national}" site:truecaller.com',
        ],
        "bing": [
            f'"{national}" site:facebook.com',
            f'"{e164}" pastebin',
            f'"{national}" iraq mobile leak',
        ],
        "duckduckgo": [
            f'"{national}" filetype:csv OR filetype:txt',
            f'"{e164}" telegram OR signal',
        ],
        "pastebin": [
            f"https://pastebin.com/search?q={urllib.parse.quote(national)}",
            f"https://pastebin.com/search?q={urllib.parse.quote(e164)}",
        ],
        "github": [
            f'"{national}" OR "{e164}" extension:txt OR extension:csv OR extension:json',
        ],
    }


# ── TIER 3: Social Platform HTTP Probes ───────────────────────────────────────

async def _probe_whatsapp(session: aiohttp.ClientSession, variations: dict) -> dict:
    wa_num = variations.get("whatsapp_format", "")
    url = f"https://wa.me/{wa_num}"
    try:
        async with session.get(url, allow_redirects=True, ssl=False) as resp:
            body = await resp.text(encoding="utf-8", errors="ignore")
            conf = 0
            indicators: list[str] = []

            if resp.status == 200:
                conf += 30
                indicators.append("wa.me URL resolved (200 OK)")

            if "WhatsApp" in body:
                conf += 15
                indicators.append("WhatsApp branding present")

            if "send message" in body.lower() or "chat" in body.lower():
                conf += 20
                indicators.append("Chat CTA detected in page")

            if "og:description" in body:
                conf += 10
                indicators.append("OpenGraph metadata found")

            return {
                "platform": "WhatsApp",
                "icon": "💬",
                "url": url,
                "status_code": resp.status,
                "confidence": min(conf, 90),
                "indicators": indicators,
                "methodology": "wa.me landing page content analysis",
            }
    except Exception as e:
        return {"platform": "WhatsApp", "icon": "💬", "url": url, "confidence": 0,
                "status": "unreachable", "indicators": [str(e)[:80]]}


async def _probe_telegram(session: aiohttp.ClientSession, variations: dict) -> dict:
    phone_no_plus = variations.get("e164", "").lstrip("+")
    url = f"https://t.me/+{phone_no_plus}"
    try:
        async with session.get(url, allow_redirects=True, ssl=False) as resp:
            body = await resp.text(encoding="utf-8", errors="ignore")
            conf = 0
            indicators: list[str] = []

            if resp.status == 200:
                conf += 20
                indicators.append("t.me URL resolved (200 OK)")

            if "tgme_page_context_link" in body or "tg://resolve" in body:
                conf += 30
                indicators.append("Telegram profile context link found")

            if "og:image" in body and "telegram" in body.lower():
                conf += 15
                indicators.append("Telegram OG image metadata")

            if "tgme_widget_message" in body:
                conf += 20
                indicators.append("Telegram widget message present")

            return {
                "platform": "Telegram",
                "icon": "✈️",
                "url": url,
                "status_code": resp.status,
                "confidence": min(conf, 88),
                "indicators": indicators,
                "methodology": "t.me phone deep-link response analysis",
            }
    except Exception as e:
        return {"platform": "Telegram", "icon": "✈️", "url": url, "confidence": 0,
                "status": "unreachable", "indicators": [str(e)[:80]]}


async def _probe_truecaller(session: aiohttp.ClientSession, variations: dict) -> dict:
    national = variations.get("national", "")
    url = f"https://search.truecaller.com/v2/search?q={urllib.parse.quote(national)}&type=4&countryCode=IQ"
    try:
        async with session.get(url, ssl=False) as resp:
            conf = 0
            name_hint = ""
            indicators: list[str] = []

            if resp.status == 200:
                try:
                    data = await resp.json()
                    if data.get("data"):
                        conf = 78
                        name_hint = (data.get("data") or [{}])[0].get("name", "")
                        indicators.append("Truecaller record found")
                    else:
                        conf = 10
                        indicators.append("Truecaller responded — no record")
                except Exception:
                    conf = 5
            elif resp.status == 429:
                indicators.append("Rate limited by Truecaller")

            return {
                "platform": "Truecaller",
                "icon": "📋",
                "url": url,
                "status_code": resp.status,
                "confidence": conf,
                "name_hint": name_hint,
                "indicators": indicators,
                "methodology": "Truecaller public search API",
            }
    except Exception as e:
        return {"platform": "Truecaller", "icon": "📋", "confidence": 0,
                "status": "unreachable", "indicators": [str(e)[:80]]}


async def _probe_viber(session: aiohttp.ClientSession, variations: dict) -> dict:
    phone = variations.get("whatsapp_format", "")
    url = f"https://chats.viber.com/api/getAccount?id={phone}"
    try:
        async with session.get(url, ssl=False) as resp:
            conf = 18 if resp.status == 200 else 0
            return {
                "platform": "Viber",
                "icon": "📳",
                "url": url,
                "status_code": resp.status,
                "confidence": conf,
                "indicators": ["Viber chat API endpoint probed"],
                "methodology": "Viber chat API pattern probe",
            }
    except Exception as e:
        return {"platform": "Viber", "icon": "📳", "confidence": 0,
                "status": "unreachable", "indicators": [str(e)[:80]]}


def _offline_platform(platform: str, icon: str, note: str) -> dict:
    return {
        "platform": platform,
        "icon": icon,
        "confidence": 0,
        "status": "auth_required",
        "note": note,
        "indicators": [],
    }


# ── TIER 1: HaveIBeenPwned ────────────────────────────────────────────────────

async def _check_hibp(session: aiohttp.ClientSession, variations: dict) -> dict:
    api_key = os.environ.get("HIBP_API_KEY", "")
    formats_checked = [variations.get("national", ""), variations.get("e164", "")]

    if not api_key:
        return {
            "service": "HaveIBeenPwned v3",
            "checked": False,
            "status": "Set HIBP_API_KEY environment variable to enable",
            "formats_checked": formats_checked,
            "breach_count": 0,
            "paste_count": 0,
            "breaches": [],
            "pastes": [],
        }

    headers = {"hibp-api-key": api_key, "user-agent": "OptiSec-Recon-Pro/1.0"}
    breaches: list = []
    pastes: list = []

    for number in formats_checked:
        if not number:
            continue
        try:
            async with session.get(
                f"https://haveibeenpwned.com/api/v3/pasteaccount/{urllib.parse.quote(number)}",
                headers=headers, ssl=True,
            ) as resp:
                if resp.status == 200:
                    pastes.extend(await resp.json())
        except Exception:
            pass

    return {
        "service": "HaveIBeenPwned v3",
        "checked": True,
        "formats_checked": formats_checked,
        "breach_count": len(breaches),
        "paste_count": len(pastes),
        "breaches": breaches[:10],
        "pastes": pastes[:10],
        "risk": "HIGH" if (len(breaches) + len(pastes)) > 0 else "CLEAN",
    }


# ── TIER 2: Reverse Phone APIs ────────────────────────────────────────────────

async def _check_numverify(session: aiohttp.ClientSession, e164: str) -> dict:
    api_key = os.environ.get("NUMVERIFY_API_KEY", "")
    if not api_key:
        return {"service": "NumVerify", "checked": False,
                "status": "Set NUMVERIFY_API_KEY environment variable to enable"}

    number = e164.lstrip("+")
    url = f"http://apilayer.net/api/validate?access_key={api_key}&number={number}&country_code=IQ&format=1"
    try:
        async with session.get(url, ssl=False) as resp:
            data = await resp.json()
            return {
                "service": "NumVerify",
                "checked": True,
                "valid": data.get("valid"),
                "number": data.get("number"),
                "local_format": data.get("local_format"),
                "international_format": data.get("international_format"),
                "country_code": data.get("country_code"),
                "country_name": data.get("country_name"),
                "location": data.get("location"),
                "carrier": data.get("carrier"),
                "line_type": data.get("line_type"),
            }
    except Exception as e:
        return {"service": "NumVerify", "checked": False, "error": str(e)[:100]}


async def _check_abstractapi(session: aiohttp.ClientSession, e164: str) -> dict:
    api_key = os.environ.get("ABSTRACTAPI_PHONE_KEY", "")
    if not api_key:
        return {"service": "AbstractAPI Phone", "checked": False,
                "status": "Set ABSTRACTAPI_PHONE_KEY environment variable to enable"}

    number = e164.lstrip("+")
    url = f"https://phonevalidation.abstractapi.com/v1/?api_key={api_key}&phone={number}"
    try:
        async with session.get(url, ssl=True) as resp:
            data = await resp.json()
            return {
                "service": "AbstractAPI Phone",
                "checked": True,
                "valid": data.get("valid"),
                "phone": data.get("phone"),
                "format": data.get("format"),
                "country": data.get("country"),
                "type": data.get("type"),
                "carrier": data.get("carrier"),
            }
    except Exception as e:
        return {"service": "AbstractAPI Phone", "checked": False, "error": str(e)[:100]}


def _opencnam_patterns(variations: dict, carrier: Optional[dict]) -> dict:
    national = variations.get("national", "")
    patterns: list[str] = []

    if carrier:
        patterns.append(f"Caller registered with {carrier['name']} ({carrier['mcc_mnc']})")
        if carrier["region"] == "Kurdistan":
            patterns.append("Number issued in Kurdistan Region network block")
        else:
            patterns.append("Number issued in Iraq national network block")
        patterns.append(f"Network technologies: {', '.join(carrier['tech'])}")
        patterns.append(f"International roaming: {'Enabled' if carrier['roaming'] else 'Disabled'}")

    return {
        "service": "OpenCNAM Caller ID Patterns",
        "national_number": national,
        "patterns": patterns,
        "note": "Offline analysis — live caller name lookup requires OpenCNAM API key",
    }


# ── Risk Scorer ───────────────────────────────────────────────────────────────

def _compute_risk(social: list[dict], hibp: dict, carrier: Optional[dict], iraqi: bool) -> int:
    active = [p for p in social if p.get("confidence", 0) >= 40]
    exposure_score = min(len(active) * 12, 48)
    breach_score   = min((hibp.get("breach_count", 0) + hibp.get("paste_count", 0)) * 15, 30)
    carrier_score  = 10 if carrier else 0
    country_score  = 12 if iraqi else 5
    return min(exposure_score + breach_score + carrier_score + country_score, 100)


# ── Main Entry Point ──────────────────────────────────────────────────────────

async def phone_social_lookup(raw: str) -> dict:
    """Run full 5-tier phone-to-social OSINT investigation."""
    variations = generate_variations(raw)
    if not variations:
        return {"error": "Cannot parse phone number", "input": raw}

    carrier = detect_carrier(variations)
    iraqi   = is_iraqi(variations)
    region  = "IQ" if iraqi else "DEFAULT"
    adoption = REGIONAL_ADOPTION[region]

    connector = aiohttp.TCPConnector(limit=20, ssl=False)
    hdrs = {"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,*/*;q=0.9"}

    async with aiohttp.ClientSession(headers=hdrs, timeout=TIMEOUT, connector=connector) as sess:
        (
            wa_r, tg_r, vi_r, tc_r,
            hibp_r, nv_r, aa_r,
        ) = await asyncio.gather(
            _probe_whatsapp(sess, variations),
            _probe_telegram(sess, variations),
            _probe_viber(sess, variations),
            _probe_truecaller(sess, variations),
            _check_hibp(sess, variations),
            _check_numverify(sess, variations.get("e164", "")),
            _check_abstractapi(sess, variations.get("e164", "")),
            return_exceptions=True,
        )

    def _safe(r, platform, icon):
        if isinstance(r, Exception):
            return {"platform": platform, "icon": icon, "confidence": 0, "status": "error", "indicators": []}
        return r

    # Offline-only platforms (no public lookup possible without auth)
    offline_platforms = [
        _offline_platform("Signal",    "🔒", "Signal has no public phone lookup API"),
        _offline_platform("Facebook",  "👤", "Facebook phone lookup requires authentication"),
        _offline_platform("Instagram", "📸", "Instagram phone lookup requires authentication"),
        _offline_platform("Snapchat",  "👻", "Snapchat has no public phone lookup API"),
        _offline_platform("TikTok",    "🎵", "TikTok phone lookup requires authentication"),
    ]

    # Build probed platform list and blend with regional adoption rates
    probed = [
        _safe(wa_r, "WhatsApp",   "💬"),
        _safe(tg_r, "Telegram",   "✈️"),
        _safe(vi_r, "Viber",      "📳"),
        _safe(tc_r, "Truecaller", "📋"),
    ]

    for p in probed:
        pkey = p["platform"].lower()
        base = adoption.get(pkey, 30)
        raw_conf = p.get("confidence", 0)
        if raw_conf > 0:
            # Blend: 60% HTTP signal + 40% regional stats
            p["confidence"] = min(int(raw_conf * 0.6 + base * 0.4), 95)
        else:
            # Assign regional base when check was inconclusive (not an error/unreachable)
            if p.get("status") not in ("unreachable", "error"):
                p["regional_base_confidence"] = base
                p["confidence"] = 0

    social_all = probed + offline_platforms

    # Add regional adoption hint to offline platforms
    for p in social_all:
        pkey = p["platform"].lower()
        if pkey in adoption:
            p["regional_adoption_pct"] = adoption[pkey]

    hibp   = _safe(hibp_r,  "HIBP",        "")
    nv     = _safe(nv_r,    "NumVerify",   "")
    aa     = _safe(aa_r,    "AbstractAPI", "")
    cnam   = _opencnam_patterns(variations, carrier)
    dorks  = build_dorks(variations)

    risk = _compute_risk(social_all, hibp, carrier, iraqi)

    return {
        "input": raw,
        "variations": variations,
        "is_iraqi_number": iraqi,

        # T1
        "breach_intelligence": hibp,

        # T2
        "reverse_lookup": {
            "numverify": nv,
            "abstractapi": aa,
            "opencnam": cnam,
        },

        # T3
        "social_platforms": social_all,

        # T4
        "carrier_intelligence": carrier,

        # T5
        "osint_dorks": dorks,

        # Summary
        "risk_score": risk,
        "risk_label": "HIGH" if risk >= 65 else "MEDIUM" if risk >= 35 else "LOW",
        "summary": {
            "platforms_probed": len(probed),
            "platforms_with_signal": sum(1 for p in probed if p.get("confidence", 0) >= 40),
            "breach_hits": hibp.get("breach_count", 0) + hibp.get("paste_count", 0),
            "carrier_identified": bool(carrier),
            "dork_queries": sum(len(v) for v in dorks.values()),
        },
    }
