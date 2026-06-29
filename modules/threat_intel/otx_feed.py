"""AlienVault OTX live threat feed integration."""
import hashlib
import logging
from datetime import datetime
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_OTX_BASE = "https://otx.alienvault.com/api/v1"
_HEADERS_BASE = {
    "User-Agent": "OPTISEC-Platform/4.0 (Security Research)",
    "Accept": "application/json",
}

# Map OTX indicator types to our internal types
_TYPE_MAP = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "URI": "url",
    "FileHash-MD5": "hash_md5",
    "FileHash-SHA256": "hash_sha256",
    "FileHash-SHA1": "hash_sha1",
    "FileHash-SHA512": "hash_sha512",
    "CVE": "cve",
    "email": "email",
    "CIDR": "cidr",
    "Mutex": "mutex",
    "filepath": "filepath",
    "YARARule": "yara",
}

_TLP_MAP = {
    "white": "WHITE",
    "green": "GREEN",
    "amber": "AMBER",
    "red": "RED",
}


def _session(api_key: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({**_HEADERS_BASE, "X-OTX-API-KEY": api_key})
    return s


def fetch_otx_pulses(api_key: str, limit: int = 50) -> list:
    """Fetch latest pulses from AlienVault OTX activity feed and return normalized IOCs."""
    sess = _session(api_key)
    iocs: list = []
    page = 1

    while len(iocs) < limit:
        try:
            resp = sess.get(
                f"{_OTX_BASE}/pulses/activity",
                params={"limit": 10, "page": page},
                timeout=20,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.RequestException as exc:
            logger.error("OTX API request failed: %s", exc)
            raise

        pulses = data.get("results", [])
        if not pulses:
            break

        for pulse in pulses:
            pulse_name = pulse.get("name", "Unknown Pulse")
            pulse_tlp = _TLP_MAP.get(pulse.get("tlp", "white").lower(), "WHITE")
            malware_families = pulse.get("malware_families", [])
            if malware_families:
                malware_label = malware_families[0].get("display_name", pulse_name)
            else:
                malware_label = pulse_name[:50]
            pulse_created = pulse.get("created", "")
            pulse_modified = pulse.get("modified", "")
            author = pulse.get("author_name", "OTX")
            adversary = pulse.get("adversary", "")

            for indicator in pulse.get("indicators", []):
                raw_type = indicator.get("type", "")
                ioc_type = _TYPE_MAP.get(raw_type, raw_type.lower() or "unknown")
                value = indicator.get("indicator", "")
                if not value:
                    continue

                title = indicator.get("title", "") or malware_label
                ioc_id = hashlib.md5(f"{ioc_type}:{value}".encode()).hexdigest()[:10]

                iocs.append({
                    "id": ioc_id,
                    "type": ioc_type,
                    "value": value,
                    "malware": malware_label,
                    "confidence": 80,
                    "source": "ALIENVAULT-OTX",
                    "source_label": f"OTX:{author}",
                    "tlp": pulse_tlp,
                    "pulse_name": pulse_name,
                    "title": title,
                    "adversary": adversary,
                    "first_seen": indicator.get("created", pulse_created),
                    "last_seen": pulse_modified or pulse_created,
                    "tags": pulse.get("tags", []),
                    "threat_score": _score_indicator(indicator, pulse),
                })

                if len(iocs) >= limit:
                    return iocs

        if not data.get("next"):
            break
        page += 1

    return iocs


def _score_indicator(indicator: dict, pulse: dict) -> int:
    base = 70
    itype = indicator.get("type", "")
    if itype in ("FileHash-MD5", "FileHash-SHA256", "FileHash-SHA1"):
        base = 85
    elif itype in ("IPv4", "IPv6"):
        base = 80
    elif itype == "CVE":
        base = 90
    elif itype in ("URL", "URI"):
        base = 78

    if pulse.get("malware_families"):
        base = min(100, base + 5)
    if len(pulse.get("targeted_countries", [])) > 3:
        base = min(100, base + 5)
    if pulse.get("adversary"):
        base = min(100, base + 8)

    return base


def test_otx_connection(api_key: str) -> dict:
    """Test OTX API connection and return user account info."""
    sess = _session(api_key)
    try:
        resp = sess.get(f"{_OTX_BASE}/user/me", timeout=15)
        resp.raise_for_status()
        user = resp.json()
        return {
            "connected": True,
            "username": user.get("username", ""),
            "pulse_count": user.get("pulse_count", 0),
            "indicator_count": user.get("indicator_count", 0),
            "member_since": user.get("member_since", ""),
            "user_id": user.get("user_id", 0),
        }
    except requests.exceptions.HTTPError as exc:
        return {
            "connected": False,
            "error": f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
        }
    except requests.exceptions.RequestException as exc:
        return {"connected": False, "error": str(exc)}
