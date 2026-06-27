"""Geographic Intelligence — IP geolocation via ip-api.com + ipinfo.io."""

import asyncio
import socket
import httpx

IP_API_URL = "http://ip-api.com/json/{ip}?fields=66846719"
IPINFO_URL = "https://ipinfo.io/{ip}/json"


async def geolocate_ip(target: str) -> dict:
    ip = _resolve_to_ip(target)
    if not ip:
        return {"error": f"Cannot resolve '{target}' to an IP address"}

    primary, fallback = await asyncio.gather(
        _query_ip_api(ip),
        _query_ipinfo(ip),
        return_exceptions=True,
    )

    result = {"ip": ip, "input": target}

    if not isinstance(primary, Exception) and not primary.get("error"):
        result.update(primary)
    elif not isinstance(fallback, Exception) and not fallback.get("error"):
        result.update(fallback)
    else:
        result["error"] = "All geolocation providers failed"

    if "lat" in result and "lon" in result:
        result["maps_url"] = (
            f"https://www.openstreetmap.org/?mlat={result['lat']}&mlon={result['lon']}&zoom=12"
        )

    result["risk_score"] = _calc_risk(result)
    result["risk_label"] = _risk_label(result["risk_score"])
    result["intelligence_notes"] = _build_notes(result)
    return result


def _resolve_to_ip(target: str) -> str | None:
    target = target.strip()
    # Already an IP?
    try:
        socket.inet_aton(target)
        return target
    except OSError:
        pass
    # Strip protocol
    for prefix in ("https://", "http://"):
        if target.startswith(prefix):
            target = target[len(prefix):]
    target = target.split("/")[0].split(":")[0]
    try:
        return socket.gethostbyname(target)
    except Exception:
        return None


async def _query_ip_api(ip: str) -> dict:
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(IP_API_URL.format(ip=ip))
        r.raise_for_status()
        d = r.json()
        if d.get("status") == "fail":
            return {"error": d.get("message", "ip-api failed")}
        return {
            "city": d.get("city"),
            "region": d.get("regionName"),
            "country": d.get("country"),
            "country_code": d.get("countryCode"),
            "isp": d.get("isp"),
            "org": d.get("org"),
            "asn": d.get("as"),
            "lat": d.get("lat"),
            "lon": d.get("lng"),
            "timezone": d.get("timezone"),
            "proxy": d.get("proxy", False),
            "hosting": d.get("hosting", False),
            "mobile": d.get("mobile", False),
            "reverse_dns": d.get("reverse"),
            "source": "ip-api.com",
        }


async def _query_ipinfo(ip: str) -> dict:
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(IPINFO_URL.format(ip=ip))
        r.raise_for_status()
        d = r.json()
        loc = d.get("loc", "").split(",")
        lat, lon = (float(loc[0]), float(loc[1])) if len(loc) == 2 else (None, None)
        return {
            "city": d.get("city"),
            "region": d.get("region"),
            "country": d.get("country"),
            "org": d.get("org"),
            "asn": d.get("org", "").split(" ")[0] if d.get("org") else None,
            "lat": lat,
            "lon": lon,
            "timezone": d.get("timezone"),
            "reverse_dns": d.get("hostname"),
            "source": "ipinfo.io",
        }


def _calc_risk(d: dict) -> int:
    score = 10
    if d.get("proxy"):
        score += 40
    if d.get("hosting"):
        score += 20
    if d.get("country_code") in ("RU", "CN", "KP", "IR"):
        score += 20
    if not d.get("city"):
        score += 10
    return min(score, 100)


def _risk_label(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _build_notes(d: dict) -> list:
    notes = []
    if d.get("proxy"):
        notes.append("IP flagged as proxy/VPN — identity likely masked")
    if d.get("hosting"):
        notes.append("Hosting/datacenter IP — possibly a server or bot source")
    if d.get("mobile"):
        notes.append("Mobile carrier IP — user on cellular network")
    cc = d.get("country_code", "")
    if cc == "IQ":
        notes.append("Iraqi IP — ISPs include Zain, Asiacell, Korek, ITC, EarthLink")
    if not notes:
        notes.append("Residential IP from legitimate network")
    return notes
