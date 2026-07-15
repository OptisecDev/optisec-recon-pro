"""abuse.ch URLhaus live threat feed integration.

Mirrors modules/threat_intel/otx_feed.py's shape (session-per-call,
short-TTL in-memory cache, one "fetch recent" function returning
normalized IOC dicts) so modules/ioc/ioc_engine.py can plug this in as
just another source client alongside OTX. URLhaus requires an Auth-Key
(free, self-service at https://auth.abuse.ch/) on every request — there is
no anonymous access, unlike this app's earlier (incorrect) assumption.
"""
import hashlib
import logging
import time

import requests

logger = logging.getLogger(__name__)

# Simple in-memory cache: {api_key_prefix: (timestamp, iocs)}
_CACHE: dict = {}
_CACHE_TTL = 300  # 5 minutes

_URLHAUS_BASE = "https://urlhaus-api.abuse.ch/v1"
_HEADERS_BASE = {
    "User-Agent": "OPTISEC-Platform/4.0 (Security Research)",
    "Accept": "application/json",
}


def _session(api_key: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({**_HEADERS_BASE, "Auth-Key": api_key})
    return s


def fetch_urlhaus_recent(api_key: str, limit: int = 50) -> list:
    """Fetch recently added malware URLs from URLhaus and return normalized
    IOCs. GET /v1/urls/recent/ returns at most 1000 entries added in the
    last 3 days; there is no pagination to walk (unlike OTX's activity
    feed), so this is a single request per call."""
    cache_key = api_key[:8]
    now = time.time()
    if cache_key in _CACHE:
        ts, cached = _CACHE[cache_key]
        if now - ts < _CACHE_TTL:
            return cached[:limit]

    sess = _session(api_key)
    try:
        resp = sess.get(
            f"{_URLHAUS_BASE}/urls/recent/",
            params={"limit": max(1, min(limit, 1000))},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.RequestException as exc:
        logger.error("URLhaus API request failed: %s", exc)
        raise

    iocs: list = []
    if data.get("query_status") == "ok":
        for entry in data.get("urls", []):
            value = entry.get("url", "")
            if not value:
                continue

            tags = entry.get("tags") or []
            malware_label = tags[0] if tags else (entry.get("threat") or "Unknown")
            reporter = entry.get("reporter", "anonymous")
            ioc_id = hashlib.md5(f"url:{value}".encode()).hexdigest()[:10]

            iocs.append({
                "id": ioc_id,
                "type": "url",
                "value": value,
                "malware": malware_label,
                "confidence": _score_entry(entry),
                "source": "URLHAUS",
                "source_label": f"URLhaus:{reporter}",
                "host": entry.get("host", ""),
                "first_seen": entry.get("date_added", ""),
                "last_seen": entry.get("date_added", ""),
                "tags": tags,
                "threat_score": _score_entry(entry),
            })

    _CACHE[cache_key] = (now, iocs)
    return iocs[:limit]


def _score_entry(entry: dict) -> int:
    # Every URLhaus entry is a confirmed malware-distribution URL (unlike
    # OTX pulses, which mix confidence levels), so the baseline starts high.
    base = 80
    if entry.get("url_status") == "online":
        base += 10
    if entry.get("tags"):
        base += 5
    return min(100, base)


def test_urlhaus_connection(api_key: str) -> dict:
    """Test URLhaus API connectivity/Auth-Key validity."""
    sess = _session(api_key)
    try:
        resp = sess.get(f"{_URLHAUS_BASE}/urls/recent/", params={"limit": 1}, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        return {"connected": data.get("query_status") == "ok", "query_status": data.get("query_status")}
    except requests.exceptions.HTTPError as exc:
        return {
            "connected": False,
            "error": f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
        }
    except requests.exceptions.RequestException as exc:
        return {"connected": False, "error": str(exc)}
