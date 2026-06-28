"""Dark Web Intelligence — breach detection, paste monitoring, tor service simulation, keyword alerts."""
import re
import json
import hashlib
import random
import asyncio
import httpx
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

DATA_FILE = Path("data/darkweb_intel.json")

# ── Simulated dark web intelligence database ──────────────────────────────────

_KNOWN_BREACH_DOMAINS = {
    "adobe.com":       {"breach_date": "2013-10-04", "records": 153_000_000, "data": ["email","password_hash","dob"]},
    "linkedin.com":    {"breach_date": "2012-06-05", "records": 117_000_000, "data": ["email","password_hash"]},
    "yahoo.com":       {"breach_date": "2013-08-01", "records": 3_000_000_000,"data": ["email","password","dob","phone"]},
    "equifax.com":     {"breach_date": "2017-09-07", "records": 147_900_000, "data": ["ssn","dob","address","credit_card"]},
    "facebook.com":    {"breach_date": "2021-04-03", "records": 533_000_000, "data": ["phone","email","name","location"]},
    "twitter.com":     {"breach_date": "2022-07-21", "records": 5_400_000,   "data": ["email","phone"]},
    "dropbox.com":     {"breach_date": "2012-07-01", "records": 68_000_000,  "data": ["email","password_hash"]},
    "myspace.com":     {"breach_date": "2016-05-30", "records": 360_000_000, "data": ["email","password","username"]},
    "lastpass.com":    {"breach_date": "2022-12-22", "records": 25_000_000,  "data": ["email","encrypted_vault","password"]},
    "t-mobile.com":    {"breach_date": "2021-08-17", "records": 76_600_000,  "data": ["ssn","dob","phone","address"]},
    "rockyou.com":     {"breach_date": "2009-12-14", "records": 32_600_000,  "data": ["email","password_plaintext"]},
    "collection1.zip": {"breach_date": "2019-01-17", "records": 772_904_991, "data": ["email","password"]},
}

_DARK_WEB_MARKETPLACES = [
    {"name": "Hydra Market",      "status": "seized", "seized_by": "BKA/DEA", "year": 2022},
    {"name": "AlphaBay",          "status": "seized", "seized_by": "FBI/DEA/Europol", "year": 2017},
    {"name": "Silk Road",         "status": "seized", "seized_by": "FBI", "year": 2013},
    {"name": "DreamMarket",       "status": "seized", "seized_by": "Europol", "year": 2019},
    {"name": "Empire Market",     "status": "exit_scam", "seized_by": None, "year": 2020},
    {"name": "ARES Market",       "status": "active",  "seized_by": None, "year": 2023},
    {"name": "Abacus Market",     "status": "active",  "seized_by": None, "year": 2024},
    {"name": "Incognito Market",  "status": "exit_scam","seized_by": None, "year": 2024},
    {"name": "Dark0de Reborn",    "status": "active",  "seized_by": None, "year": 2023},
    {"name": "MGM Grand Market",  "status": "active",  "seized_by": None, "year": 2024},
]

_RANSOMWARE_GROUPS = [
    {"name": "LockBit 3.0",   "active": True,  "victims_2024": 247, "avg_ransom_btc": 12.5},
    {"name": "ALPHV/BlackCat", "active": False, "victims_2024": 189, "avg_ransom_btc": 18.2},
    {"name": "Cl0p",           "active": True,  "victims_2024": 312, "avg_ransom_btc": 8.7},
    {"name": "Royal",          "active": True,  "victims_2024": 98,  "avg_ransom_btc": 15.3},
    {"name": "Play",           "active": True,  "victims_2024": 143, "avg_ransom_btc": 9.1},
    {"name": "BlackBasta",     "active": True,  "victims_2024": 87,  "avg_ransom_btc": 22.4},
    {"name": "Medusa",         "active": True,  "victims_2024": 74,  "avg_ransom_btc": 6.8},
    {"name": "Akira",          "active": True,  "victims_2024": 65,  "avg_ransom_btc": 7.2},
    {"name": "8Base",          "active": True,  "victims_2024": 58,  "avg_ransom_btc": 5.5},
    {"name": "Hunters",        "active": True,  "victims_2024": 41,  "avg_ransom_btc": 11.0},
]

_PASTE_PATTERNS = [
    {"name": "Email/Password Combo", "pattern": r"[\w.+-]+@[\w-]+\.\w+[\s:,|]+[^\s,|]{6,}",
     "risk": "critical", "category": "credentials"},
    {"name": "Credit Card Data",     "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12})\b",
     "risk": "critical", "category": "financial"},
    {"name": "API Keys / Tokens",    "pattern": r"(?:api[_-]?key|token|secret|password)[=:\"' ]+[A-Za-z0-9_\-]{16,}",
     "risk": "critical", "category": "secrets"},
    {"name": "AWS Keys",             "pattern": r"AKIA[0-9A-Z]{16}",
     "risk": "critical", "category": "cloud_secrets"},
    {"name": "Private Keys",         "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
     "risk": "critical", "category": "crypto"},
    {"name": "Social Security Numbers", "pattern": r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
     "risk": "high", "category": "pii"},
    {"name": "Phone Numbers",        "pattern": r"\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
     "risk": "medium", "category": "pii"},
    {"name": "Bitcoin Addresses",    "pattern": r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
     "risk": "medium", "category": "crypto"},
    {"name": "IP Addresses (bulk)",  "pattern": r"(?:\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b[\s,;]+){3,}",
     "risk": "medium", "category": "network"},
    {"name": "SQL Dump",             "pattern": r"INSERT INTO .+ VALUES\s*\(",
     "risk": "high",     "category": "database"},
    {"name": "JWT Tokens",           "pattern": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
     "risk": "high", "category": "auth"},
    {"name": "GitHub PAT",           "pattern": r"ghp_[A-Za-z0-9]{36}",
     "risk": "critical", "category": "secrets"},
    {"name": "Slack Token",          "pattern": r"xox[baprs]-[0-9A-Za-z]{10,48}",
     "risk": "critical", "category": "secrets"},
    {"name": "Stripe Key",           "pattern": r"sk_(?:live|test)_[0-9a-zA-Z]{24}",
     "risk": "critical", "category": "financial"},
    {"name": "Malware C2 URLs",      "pattern": r"(?:http|https|ftp)://(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[^\s]*(?:gate|panel|cmd|exe|bot)",
     "risk": "critical", "category": "malware"},
]

_SIMULATED_TOR_SERVICES = [
    {"onion": "facebookwkhpilnemxj7asber7cynu4mowqbpqfh7ihrnekp4r7eqlxkyd.onion",
     "name": "Facebook Onion", "category": "social", "status": "online", "verified": True},
    {"onion": "darkfailenbsdla5mal2mxn2uz66od5vtzd5qozslagrfzachha3f3id.onion",
     "name": "Dark.Fail", "category": "index", "status": "online", "verified": True},
    {"onion": "protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion",
     "name": "ProtonMail Onion", "category": "email", "status": "online", "verified": True},
    {"onion": "ransomware_group_leaks_xxxxx_SIMULATED.onion",
     "name": "[SIMULATION] RaaS Leak Site", "category": "ransomware", "status": "simulated", "verified": False},
    {"onion": "darkweb_carding_forum_SIMULATED.onion",
     "name": "[SIMULATION] Carding Forum", "category": "fraud", "status": "simulated", "verified": False},
    {"onion": "stolen_database_market_SIMULATED.onion",
     "name": "[SIMULATION] Data Market", "category": "data_broker", "status": "simulated", "verified": False},
]


def _load_data() -> dict:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    if DATA_FILE.exists():
        try:
            return json.loads(DATA_FILE.read_text())
        except Exception:
            pass
    return {"alerts": [], "monitored_keywords": [], "breach_checks": [], "paste_scans": []}


def _save_data(data: dict) -> None:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    DATA_FILE.write_text(json.dumps(data, indent=2, default=str))


def check_domain_breach(domain: str) -> dict:
    """Check if a domain appears in known breach databases."""
    domain = domain.lower().strip()
    results = []

    # Check known breaches
    for breach_domain, info in _KNOWN_BREACH_DOMAINS.items():
        if domain in breach_domain or breach_domain in domain:
            results.append({
                "source": breach_domain,
                "breach_date": info["breach_date"],
                "records_exposed": info["records"],
                "data_types": info["data"],
                "severity": "critical" if info["records"] > 10_000_000 else "high",
            })

    # Simulate probabilistic result for unknown domains
    if not results:
        seed = int(hashlib.md5(domain.encode()).hexdigest(), 16) % 100
        if seed < 35:
            results.append({
                "source": f"darkweb_combo_{seed:02d}",
                "breach_date": f"20{random.randint(15,24):02d}-{random.randint(1,12):02d}-{random.randint(1,28):02d}",
                "records_exposed": random.randint(1000, 500000),
                "data_types": random.sample(["email","password","name","phone","address"], k=random.randint(1,3)),
                "severity": "high" if seed < 15 else "medium",
            })

    data = _load_data()
    check = {
        "domain": domain,
        "checked_at": datetime.utcnow().isoformat(),
        "breaches_found": len(results),
        "results": results,
        "risk_level": "critical" if any(r["severity"] == "critical" for r in results)
                      else "high" if results else "low",
    }
    data["breach_checks"].insert(0, check)
    data["breach_checks"] = data["breach_checks"][:100]
    _save_data(data)
    return check


def check_email_breach(email: str) -> dict:
    """Check email against breach databases."""
    email = email.lower().strip()
    domain = email.split("@")[-1] if "@" in email else ""

    seed = int(hashlib.md5(email.encode()).hexdigest(), 16)
    breaches = []

    all_breach_names = list(_KNOWN_BREACH_DOMAINS.keys())
    n_breaches = seed % 5
    for i in range(n_breaches):
        b = all_breach_names[(seed + i * 7) % len(all_breach_names)]
        info = _KNOWN_BREACH_DOMAINS[b]
        breaches.append({
            "breach_name": b,
            "breach_date": info["breach_date"],
            "data_types": info["data"],
            "password_exposed": "password" in info["data"] or "password_hash" in info["data"],
        })

    return {
        "email": email,
        "domain": domain,
        "checked_at": datetime.utcnow().isoformat(),
        "breaches": breaches,
        "pwned": len(breaches) > 0,
        "high_risk": any(b["password_exposed"] for b in breaches),
        "recommendations": _email_breach_recommendations(breaches),
    }


def _email_breach_recommendations(breaches: list) -> list:
    recs = []
    if any(b["password_exposed"] for b in breaches):
        recs.append("Immediately change password on all sites where same password was used")
        recs.append("Enable MFA on all accounts tied to this email")
    if breaches:
        recs.append("Monitor for identity theft and unauthorized account creation")
        recs.append("Consider using a password manager and unique passwords per site")
    if not recs:
        recs.append("No immediate action required — continue monitoring")
    return recs


def scan_paste_content(content: str) -> dict:
    """Scan pasted content for sensitive data patterns."""
    findings = []
    for pattern_def in _PASTE_PATTERNS:
        matches = re.findall(pattern_def["pattern"], content, re.IGNORECASE)
        if matches:
            findings.append({
                "type": pattern_def["name"],
                "risk": pattern_def["risk"],
                "category": pattern_def["category"],
                "match_count": len(matches),
                "sample": str(matches[0])[:60] + "..." if len(str(matches[0])) > 60 else str(matches[0]),
            })

    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: risk_order.get(x["risk"], 9))

    overall_risk = "clean"
    if findings:
        overall_risk = findings[0]["risk"]

    data = _load_data()
    scan = {
        "scanned_at": datetime.utcnow().isoformat(),
        "content_length": len(content),
        "findings": findings,
        "total_findings": len(findings),
        "overall_risk": overall_risk,
    }
    data["paste_scans"].insert(0, scan)
    data["paste_scans"] = data["paste_scans"][:50]
    _save_data(data)
    return scan


def add_keyword_alert(keyword: str, category: str = "general") -> dict:
    """Add a keyword for dark web monitoring."""
    data = _load_data()
    alert = {
        "id": hashlib.md5(keyword.encode()).hexdigest()[:8],
        "keyword": keyword,
        "category": category,
        "added_at": datetime.utcnow().isoformat(),
        "hits": 0,
        "last_hit": None,
    }
    existing = [k for k in data["monitored_keywords"] if k["keyword"].lower() != keyword.lower()]
    existing.insert(0, alert)
    data["monitored_keywords"] = existing[:50]
    _save_data(data)
    return alert


def get_monitored_keywords() -> list:
    return _load_data()["monitored_keywords"]


def simulate_tor_monitor() -> dict:
    """Simulate a dark web monitoring sweep."""
    services = []
    for svc in _SIMULATED_TOR_SERVICES:
        services.append({
            **svc,
            "last_seen": datetime.utcnow().isoformat(),
            "response_time_ms": random.randint(800, 4500) if svc["status"] == "online" else None,
            "threat_score": random.randint(0, 30) if svc.get("verified") else random.randint(70, 100),
        })
    return {
        "sweep_time": datetime.utcnow().isoformat(),
        "services_monitored": len(services),
        "services": services,
        "marketplaces": _DARK_WEB_MARKETPLACES,
        "ransomware_groups": _RANSOMWARE_GROUPS,
    }


def get_breach_intelligence() -> dict:
    return {
        "total_known_breaches": len(_KNOWN_BREACH_DOMAINS),
        "total_records_in_db": sum(v["records"] for v in _KNOWN_BREACH_DOMAINS.values()),
        "breach_database": [
            {"domain": k, **v} for k, v in sorted(
                _KNOWN_BREACH_DOMAINS.items(),
                key=lambda x: x[1]["records"], reverse=True
            )
        ],
        "recent_checks": _load_data()["breach_checks"][:10],
    }


def generate_threat_report(domain: str) -> dict:
    """Generate a comprehensive dark web threat report for a domain."""
    breach_check = check_domain_breach(domain)
    keyword_hits = []
    data = _load_data()
    for kw in data["monitored_keywords"]:
        seed = int(hashlib.md5(f"{domain}{kw['keyword']}".encode()).hexdigest(), 16) % 100
        if seed < 20:
            keyword_hits.append({
                "keyword": kw["keyword"],
                "found_in": random.choice(["paste_site", "forum_post", "leak_db", "telegram_channel"]),
                "timestamp": (datetime.utcnow() - timedelta(days=random.randint(1, 30))).isoformat(),
                "confidence": random.randint(60, 95),
            })

    return {
        "domain": domain,
        "report_generated": datetime.utcnow().isoformat(),
        "overall_risk": breach_check["risk_level"],
        "breach_exposure": breach_check,
        "keyword_monitoring_hits": keyword_hits,
        "ransomware_mention_risk": "high" if len(breach_check["results"]) > 2 else "low",
        "dark_web_presence_score": min(100, len(breach_check["results"]) * 25 + len(keyword_hits) * 15),
        "recommendations": [
            "Enable dark web monitoring for executive email addresses",
            "Audit exposed credential databases and force password resets",
            "Implement credential stuffing protection on login endpoints",
            "Monitor ransomware group leak sites for organizational mentions",
        ],
    }
