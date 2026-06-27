"""AI Firewall — Deep Packet Inspection + ML-based anomaly detection."""

import re
import json
import math
import asyncio
from datetime import datetime
from collections import defaultdict
from typing import Optional


# ── Signature Rules ────────────────────────────────────────────────────────────

SIGNATURES = [
    {"id": "SQL-001", "name": "SQL Injection", "pattern": r"(?i)(union\s+select|select\s+\*|drop\s+table|insert\s+into|exec\s*\(|xp_cmdshell|1=1|'--|\bor\b\s+\d+=\d+)", "severity": "critical", "category": "sqli"},
    {"id": "XSS-001", "name": "XSS Reflected", "pattern": r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|eval\s*\(|document\.cookie|<iframe|alert\s*\()", "severity": "high", "category": "xss"},
    {"id": "LFI-001", "name": "Local File Inclusion", "pattern": r"(\.\./|\.\.\\|%2e%2e%2f|%252e|etc/passwd|etc/shadow|proc/self)", "severity": "high", "category": "lfi"},
    {"id": "SSRF-001", "name": "SSRF Attempt", "pattern": r"(?i)(169\.254\.169\.254|localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1|internal\.|metadata\.)", "severity": "high", "category": "ssrf"},
    {"id": "CMD-001", "name": "Command Injection", "pattern": r"(?i)(;ls|;cat|;id|;whoami|\$\(|`.*`|\bping\s+-[cn]|\bncat\b|\bnetcat\b|/bin/sh|/bin/bash)", "severity": "critical", "category": "cmdi"},
    {"id": "CSRF-001", "name": "CSRF Token Missing", "pattern": r"", "severity": "medium", "category": "csrf"},
    {"id": "PATH-001", "name": "Path Traversal", "pattern": r"(\.\./){2,}|(\.\.\\){2,}", "severity": "high", "category": "path_traversal"},
    {"id": "XXE-001", "name": "XXE Injection", "pattern": r"(?i)(<!ENTITY|SYSTEM\s+['\"]|PUBLIC\s+['\"]|<!DOCTYPE.*\[)", "severity": "critical", "category": "xxe"},
    {"id": "LOG4J-001", "name": "Log4Shell", "pattern": r"\$\{jndi:(ldap|rmi|dns|iiop|corba|nds|http)://", "severity": "critical", "category": "log4shell"},
    {"id": "BOT-001", "name": "Bot/Scanner Signature", "pattern": r"(?i)(nikto|sqlmap|nessus|openvas|masscan|zgrab|nuclei|burpsuite|acunetix)", "severity": "medium", "category": "scanner"},
    {"id": "PROTO-001", "name": "Protocol Abuse", "pattern": r"(?i)(gopher://|dict://|file://|ldap://|ftp://)", "severity": "high", "category": "ssrf"},
    {"id": "AUTH-001", "name": "JWT Tampering", "pattern": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.(none|None|NONE|)", "severity": "critical", "category": "auth"},
]

_compiled = [(s, re.compile(s["pattern"])) for s in SIGNATURES if s["pattern"]]


# ── Packet / Request Inspector ─────────────────────────────────────────────────

def inspect_request(
    method: str,
    path: str,
    headers: dict,
    body: str = "",
    ip: str = "",
) -> dict:
    payload = f"{method} {path} {body}"
    threats = []

    for sig, pattern in _compiled:
        if pattern.search(payload):
            threats.append({
                "rule_id": sig["id"],
                "name": sig["name"],
                "severity": sig["severity"],
                "category": sig["category"],
                "matched_in": _find_match_location(pattern, method, path, body),
            })

    anomaly = _ml_anomaly_score(method, path, headers, body)
    action = _decide_action(threats, anomaly["score"])

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": ip,
        "method": method,
        "path": path[:200],
        "threats": threats,
        "anomaly": anomaly,
        "action": action,
        "blocked": action == "block",
        "risk_score": _composite_risk(threats, anomaly["score"]),
    }


def _find_match_location(pattern, method: str, path: str, body: str) -> str:
    if pattern.search(f"{method} {path}"):
        return "url"
    if body and pattern.search(body):
        return "body"
    return "headers"


def _ml_anomaly_score(method: str, path: str, headers: dict, body: str) -> dict:
    """Heuristic anomaly scoring simulating ML model output."""
    score = 0.0
    signals = []

    # Entropy-based payload analysis
    if body:
        ent = _entropy(body)
        if ent > 4.5:
            score += 0.3
            signals.append(f"high entropy payload ({ent:.2f} bits)")

    # Unusual HTTP methods
    if method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
        score += 0.4
        signals.append(f"unusual HTTP method: {method}")

    # Path length anomaly
    if len(path) > 500:
        score += 0.25
        signals.append("unusually long URL path")

    # Null bytes
    if "\x00" in path or "\x00" in body:
        score += 0.6
        signals.append("null byte injection attempt")

    # Double encoding
    if "%25" in path.lower() or "%2525" in path.lower():
        score += 0.4
        signals.append("double URL encoding detected")

    # Missing standard headers
    ua = headers.get("user-agent", headers.get("User-Agent", ""))
    if not ua:
        score += 0.2
        signals.append("missing User-Agent header")

    # Excessive parameters
    param_count = path.count("=") + body.count("=")
    if param_count > 30:
        score += 0.2
        signals.append(f"excessive parameters ({param_count})")

    return {"score": min(score, 1.0), "signals": signals}


def _entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for c in data:
        freq[c] += 1
    length = len(data)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def _composite_risk(threats: list, anomaly_score: float) -> float:
    severity_weights = {"critical": 0.9, "high": 0.7, "medium": 0.4, "low": 0.2}
    threat_score = max((severity_weights.get(t["severity"], 0.3) for t in threats), default=0.0)
    return round(min(threat_score * 0.7 + anomaly_score * 0.3, 1.0), 3)


def _decide_action(threats: list, anomaly_score: float) -> str:
    critical = any(t["severity"] == "critical" for t in threats)
    high_threat = len([t for t in threats if t["severity"] in ("critical", "high")]) >= 2
    if critical or high_threat or anomaly_score > 0.8:
        return "block"
    if threats or anomaly_score > 0.5:
        return "alert"
    return "allow"


# ── Batch Analysis ─────────────────────────────────────────────────────────────

async def analyze_log_sample(log_lines: list[str]) -> dict:
    """Parse Apache/Nginx-style log lines and inspect each request."""
    apache_pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[.*?\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+)'
    )
    results = []
    for line in log_lines[:500]:
        m = apache_pattern.match(line)
        if m:
            result = inspect_request(
                method=m.group("method"),
                path=m.group("path"),
                headers={},
                body="",
                ip=m.group("ip"),
            )
            result["status_code"] = int(m.group("status"))
            results.append(result)

    blocked = [r for r in results if r["action"] == "block"]
    alerted = [r for r in results if r["action"] == "alert"]
    top_threats = _top_threat_categories(results)

    return {
        "analyzed": len(results),
        "blocked": len(blocked),
        "alerted": len(alerted),
        "allowed": len(results) - len(blocked) - len(alerted),
        "top_threats": top_threats,
        "high_risk_requests": blocked[:20],
        "analyzed_at": datetime.utcnow().isoformat(),
    }


def _top_threat_categories(results: list) -> list:
    cats = defaultdict(int)
    for r in results:
        for t in r.get("threats", []):
            cats[t["category"]] += 1
    return sorted([{"category": k, "count": v} for k, v in cats.items()],
                  key=lambda x: -x["count"])[:10]


# ── Rate Limiting & IP Reputation ─────────────────────────────────────────────

_rate_tracker: dict[str, list] = defaultdict(list)


def check_rate_limit(ip: str, window_seconds: int = 60, max_requests: int = 100) -> dict:
    now = datetime.utcnow().timestamp()
    requests = _rate_tracker[ip]
    requests = [t for t in requests if now - t < window_seconds]
    requests.append(now)
    _rate_tracker[ip] = requests

    count = len(requests)
    limited = count > max_requests
    return {
        "ip": ip,
        "requests_in_window": count,
        "limit": max_requests,
        "window_seconds": window_seconds,
        "rate_limited": limited,
        "action": "block" if limited else "allow",
    }


def get_firewall_rules() -> list:
    return [{"id": s["id"], "name": s["name"], "severity": s["severity"],
             "category": s["category"], "enabled": True} for s in SIGNATURES]
