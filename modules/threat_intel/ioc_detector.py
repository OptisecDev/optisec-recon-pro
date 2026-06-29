"""IOC Detection — checks IPs, domains, and file hashes against threat intelligence feeds."""
import os
import re
import hashlib
import ipaddress
import requests
from typing import Dict, Any, Optional

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
SHODAN_KEY = os.environ.get("SHODAN_API_KEY", "")

# Well-known malicious IP ranges / TOR exit node check endpoint
TOR_CHECK_URL = "https://check.torproject.org/torbulkexitlist"
_TOR_CACHE: set = set()

SEVERITY_MAP = {
    (0, 15): "CLEAN",
    (16, 40): "SUSPICIOUS",
    (41, 70): "MALICIOUS",
    (71, 100): "CRITICAL",
}


def _get_severity(score: int) -> str:
    for (lo, hi), label in SEVERITY_MAP.items():
        if lo <= score <= hi:
            return label
    return "UNKNOWN"


def check_ip(ip: str) -> Dict[str, Any]:
    """Check an IP address against AbuseIPDB and Shodan."""
    result: Dict[str, Any] = {
        "ioc": ip,
        "type": "ip",
        "verdict": "UNKNOWN",
        "score": 0,
        "sources": [],
        "country": None,
        "isp": None,
        "is_tor": False,
        "reports": [],
        "tags": [],
    }

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        result["error"] = "Invalid IP address"
        return result

    # AbuseIPDB
    if ABUSEIPDB_KEY:
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                result["score"] = max(result["score"], score)
                result["country"] = data.get("countryCode")
                result["isp"] = data.get("isp")
                result["is_tor"] = data.get("isTor", False)
                result["sources"].append("AbuseIPDB")
                result["tags"] = data.get("usageType", "").split(",") if data.get("usageType") else []
                result["reports"] = [
                    {"comment": r.get("comment", ""), "reported_at": r.get("reportedAt", "")}
                    for r in (data.get("reports") or [])[:5]
                ]
        except Exception as e:
            result["sources"].append(f"AbuseIPDB (error: {e})")
    else:
        result["sources"].append("AbuseIPDB (no API key)")

    # Shodan
    if SHODAN_KEY:
        try:
            resp = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": SHODAN_KEY},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                result["country"] = result["country"] or data.get("country_code")
                result["isp"] = result["isp"] or data.get("isp")
                result["sources"].append("Shodan")
                open_ports = [p["port"] for p in data.get("data", [])]
                if open_ports:
                    result["tags"].append(f"Ports: {','.join(str(p) for p in open_ports[:8])}")
                if "honeypot" in str(data.get("tags", [])).lower():
                    result["tags"].append("honeypot")
                    result["score"] = max(result["score"], 60)
        except Exception:
            result["sources"].append("Shodan (error)")

    result["verdict"] = _get_severity(result["score"])
    return result


def check_domain(domain: str) -> Dict[str, Any]:
    """Check a domain against VirusTotal and threat feeds."""
    domain = domain.lower().strip().lstrip("http://").lstrip("https://").split("/")[0]
    result: Dict[str, Any] = {
        "ioc": domain,
        "type": "domain",
        "verdict": "UNKNOWN",
        "score": 0,
        "sources": [],
        "categories": [],
        "malicious_votes": 0,
        "suspicious_votes": 0,
        "total_votes": 0,
        "tags": [],
    }

    if VIRUSTOTAL_KEY:
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": VIRUSTOTAL_KEY},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) or 1
                score = int((malicious + suspicious * 0.5) / total * 100)
                result["score"] = score
                result["malicious_votes"] = malicious
                result["suspicious_votes"] = suspicious
                result["total_votes"] = total
                result["categories"] = list(data.get("categories", {}).values())[:3]
                result["tags"] = data.get("tags", [])
                result["sources"].append("VirusTotal")
        except Exception as e:
            result["sources"].append(f"VirusTotal (error: {e})")
    else:
        result["sources"].append("VirusTotal (no API key)")

    result["verdict"] = _get_severity(result["score"])
    return result


def check_hash(file_hash: str) -> Dict[str, Any]:
    """Check a file hash (MD5/SHA1/SHA256) against VirusTotal."""
    result: Dict[str, Any] = {
        "ioc": file_hash,
        "type": "hash",
        "verdict": "UNKNOWN",
        "score": 0,
        "sources": [],
        "file_name": None,
        "file_type": None,
        "malicious_votes": 0,
        "total_votes": 0,
        "tags": [],
    }

    if not re.match(r'^[a-fA-F0-9]{32,64}$', file_hash):
        result["error"] = "Invalid hash format (MD5/SHA1/SHA256 expected)"
        return result

    if VIRUSTOTAL_KEY:
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": VIRUSTOTAL_KEY},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) or 1
                score = int(malicious / total * 100)
                result["score"] = score
                result["malicious_votes"] = malicious
                result["total_votes"] = total
                result["file_name"] = (data.get("meaningful_name") or
                                        next(iter(data.get("names", [])), None))
                result["file_type"] = data.get("type_description")
                result["tags"] = data.get("tags", [])
                result["sources"].append("VirusTotal")
            elif resp.status_code == 404:
                result["verdict"] = "NOT_FOUND"
                result["sources"].append("VirusTotal (hash not in database)")
                return result
        except Exception as e:
            result["sources"].append(f"VirusTotal (error: {e})")
    else:
        result["sources"].append("VirusTotal (no API key)")

    result["verdict"] = _get_severity(result["score"])
    return result


def bulk_check(iocs: list) -> list:
    """Check multiple IOCs, auto-detecting type."""
    results = []
    for ioc in iocs:
        ioc = ioc.strip()
        if not ioc:
            continue
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ioc):
            results.append(check_ip(ioc))
        elif re.match(r'^[a-fA-F0-9]{32,64}$', ioc):
            results.append(check_hash(ioc))
        else:
            results.append(check_domain(ioc))
    return results


def compute_hash(data: bytes, algorithm: str = "sha256") -> str:
    h = hashlib.new(algorithm)
    h.update(data)
    return h.hexdigest()
