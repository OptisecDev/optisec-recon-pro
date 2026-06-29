"""Honeypot integration — detect scanners, bots, and attackers via HTTP:BL and threat feeds."""
import os
import socket
import requests
from typing import Dict, Any

HTTPBL_KEY = os.environ.get("HTTPBL_ACCESS_KEY", "")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

# HTTP:BL visitor types
HTTPBL_TYPES = {
    0: "Search Engine",
    1: "Suspicious",
    2: "Harvester",
    4: "Comment Spammer",
    3: "Suspicious + Harvester",
    5: "Suspicious + Comment Spammer",
    6: "Harvester + Comment Spammer",
    7: "Suspicious + Harvester + Comment Spammer",
}


def check_ip_honeypot(ip: str) -> Dict[str, Any]:
    """Check an IP against Project Honeypot HTTP:BL via DNS lookup."""
    result: Dict[str, Any] = {
        "ip": ip,
        "is_threat": False,
        "threat_type": None,
        "threat_score": 0,
        "last_activity_days": None,
        "sources": [],
        "verdict": "CLEAN",
        "details": {},
    }

    # Reverse the IP for the DNS query
    reversed_ip = ".".join(reversed(ip.split(".")))

    # HTTP:BL DNS check
    if HTTPBL_KEY:
        query = f"{HTTPBL_KEY}.{reversed_ip}.dnsbl.httpbl.org"
        try:
            answer = socket.gethostbyname(query)
            parts = answer.split(".")
            if len(parts) == 4 and parts[0] == "127":
                last_activity = int(parts[1])
                threat_score = int(parts[2])
                visitor_type = int(parts[3])

                result["is_threat"] = visitor_type > 0
                result["threat_type"] = HTTPBL_TYPES.get(visitor_type, f"Type {visitor_type}")
                result["threat_score"] = threat_score
                result["last_activity_days"] = last_activity
                result["sources"].append("Project Honeypot HTTP:BL")
                result["details"]["httpbl"] = {
                    "last_seen_days_ago": last_activity,
                    "score": threat_score,
                    "type": result["threat_type"],
                }

                if threat_score >= 75:
                    result["verdict"] = "CRITICAL"
                elif threat_score >= 50:
                    result["verdict"] = "HIGH"
                elif threat_score >= 25:
                    result["verdict"] = "MEDIUM"
                elif visitor_type > 0:
                    result["verdict"] = "LOW"
        except socket.gaierror:
            # No record = clean
            result["sources"].append("Project Honeypot HTTP:BL (clean)")
        except Exception as e:
            result["sources"].append(f"Project Honeypot HTTP:BL (error: {e})")
    else:
        result["sources"].append("Project Honeypot (HTTPBL_ACCESS_KEY not set)")

    # AbuseIPDB cross-check for honeypot category
    if ABUSEIPDB_KEY:
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 30},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                result["details"]["abuseipdb_score"] = score
                result["sources"].append("AbuseIPDB")
                if score > 50 and not result["is_threat"]:
                    result["is_threat"] = True
                    result["verdict"] = "HIGH"
                    result["threat_type"] = result["threat_type"] or "Reported abusive IP"
        except Exception:
            pass

    return result


def deploy_honeypot_endpoint(endpoint_name: str) -> Dict[str, Any]:
    """Generate a honeypot trap endpoint configuration."""
    traps = {
        "admin": {
            "path": f"/{endpoint_name}",
            "description": "Fake admin panel that logs all access attempts",
            "response": {"status": 200, "body": "<html><body><h1>Admin Panel</h1><form>...</form></body></html>"},
            "log_fields": ["ip", "user_agent", "headers", "post_data", "timestamp"],
            "alert_on_access": True,
        },
        "api": {
            "path": f"/api/{endpoint_name}",
            "description": "Fake API endpoint that logs all requests",
            "response": {"status": 200, "body": '{"status":"ok","data":[]}'},
            "log_fields": ["ip", "method", "headers", "body", "timestamp"],
            "alert_on_access": True,
        },
        "file": {
            "path": f"/{endpoint_name}.php",
            "description": "Fake PHP file that captures shell injection attempts",
            "response": {"status": 200, "body": "<!-- debug output -->"},
            "log_fields": ["ip", "user_agent", "query_params", "post_data", "timestamp"],
            "alert_on_access": True,
        },
    }

    # Determine trap type from name
    if any(k in endpoint_name.lower() for k in ["admin", "dashboard", "panel", "cp"]):
        trap_type = "admin"
    elif any(k in endpoint_name.lower() for k in ["api", "rest", "graphql", "v1", "v2"]):
        trap_type = "api"
    else:
        trap_type = "file"

    config = traps[trap_type]
    return {
        "honeypot_name": endpoint_name,
        "trap_type": trap_type,
        "config": config,
        "setup_instructions": [
            f"Mount the honeypot at: {config['path']}",
            "Configure an alert webhook for immediate notification on access",
            "Log all requests with full headers and body for forensic analysis",
            "Consider adding canary tokens (unique links/credentials) to the response",
        ],
        "canary_token": _generate_canary_token(endpoint_name),
    }


def _generate_canary_token(seed: str) -> str:
    import hashlib
    return hashlib.md5(f"optisec-canary-{seed}".encode()).hexdigest()[:16]


def get_known_scanner_ips() -> list:
    """Return a list of well-known security scanner IP ranges to monitor."""
    return [
        {"range": "66.249.0.0/16", "owner": "Google Bot", "category": "Search Engine"},
        {"range": "207.46.13.0/24", "owner": "Bing Bot", "category": "Search Engine"},
        {"range": "40.77.167.0/24", "owner": "Bing Crawler", "category": "Search Engine"},
        {"range": "185.173.35.0/24", "owner": "Shodan", "category": "Security Scanner"},
        {"range": "198.20.69.0/24", "owner": "Censys", "category": "Security Scanner"},
        {"range": "71.6.135.0/24", "owner": "Masscan / Rapid7", "category": "Security Scanner"},
        {"range": "45.33.32.0/24", "owner": "nmap.org", "category": "Security Scanner"},
        {"range": "216.168.0.0/16", "owner": "ZoomEye", "category": "Security Scanner"},
    ]
