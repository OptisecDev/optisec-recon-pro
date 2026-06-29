"""HaveIBeenPwned API v3 integration — breach checking and dark web monitoring."""
import os
import re
import hashlib
import requests
from typing import Dict, Any, List, Optional

HIBP_KEY = os.environ.get("HIBP_API_KEY", "")
HIBP_BASE = "https://haveibeenpwned.com/api/v3"
PWNED_PASSWORDS_URL = "https://api.pwnedpasswords.com/range/"

HEADERS = {
    "hibp-api-key": HIBP_KEY,
    "User-Agent": "OPTISEC-ReconPro/3.0",
    "Accept": "application/json",
}


def check_email(email: str) -> Dict[str, Any]:
    """Check if an email address appears in known data breaches."""
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return {"email": email, "error": "Invalid email format"}

    if not HIBP_KEY:
        return {
            "email": email,
            "error": "HIBP_API_KEY not configured",
            "setup": "Get a key at https://haveibeenpwned.com/API/Key",
        }

    try:
        resp = requests.get(
            f"{HIBP_BASE}/breachedaccount/{email}",
            headers=HEADERS,
            params={"truncateResponse": False},
            timeout=15,
        )

        if resp.status_code == 404:
            return {
                "email": email,
                "pwned": False,
                "breach_count": 0,
                "breaches": [],
                "verdict": "CLEAN",
            }

        if resp.status_code == 401:
            return {"email": email, "error": "Invalid or expired HIBP API key"}

        if resp.status_code == 429:
            return {"email": email, "error": "HIBP rate limit exceeded — wait 1.5s between requests"}

        resp.raise_for_status()
        breaches = resp.json()
        severe = [b for b in breaches if b.get("IsVerified") and
                  any(d in (b.get("DataClasses") or [])
                      for d in ["Passwords", "Credit cards", "Social security numbers"])]

        return {
            "email": email,
            "pwned": True,
            "breach_count": len(breaches),
            "severe_breach_count": len(severe),
            "breaches": [
                {
                    "name": b.get("Name"),
                    "title": b.get("Title"),
                    "domain": b.get("Domain"),
                    "breach_date": b.get("BreachDate"),
                    "pwn_count": b.get("PwnCount"),
                    "data_classes": b.get("DataClasses", []),
                    "is_verified": b.get("IsVerified"),
                    "is_sensitive": b.get("IsSensitive"),
                }
                for b in breaches
            ],
            "verdict": "CRITICAL" if severe else "WARNING",
            "risk_summary": _risk_summary(breaches),
        }
    except requests.RequestException as e:
        return {"email": email, "error": str(e)}


def check_password(password: str) -> Dict[str, Any]:
    """Check a password against the HIBP Pwned Passwords database (k-anonymity)."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(f"{PWNED_PASSWORDS_URL}{prefix}", timeout=10,
                            headers={"User-Agent": "OPTISEC-ReconPro/3.0"})
        resp.raise_for_status()

        count = 0
        for line in resp.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0] == suffix:
                count = int(parts[1])
                break

        if count > 0:
            verdict = "CRITICAL" if count > 10000 else "HIGH" if count > 1000 else "MEDIUM"
            return {
                "pwned": True,
                "times_seen": count,
                "verdict": verdict,
                "recommendation": "Change this password immediately — it appears in known breach datasets.",
            }
        return {
            "pwned": False,
            "times_seen": 0,
            "verdict": "CLEAN",
            "recommendation": "Password not found in breach databases.",
        }
    except Exception as e:
        return {"error": str(e)}


def check_domain_breaches(domain: str) -> Dict[str, Any]:
    """List all breaches for a given domain."""
    if not HIBP_KEY:
        return {"domain": domain, "error": "HIBP_API_KEY not configured"}

    try:
        resp = requests.get(f"{HIBP_BASE}/breaches",
                            headers=HEADERS, params={"domain": domain}, timeout=15)
        if resp.status_code == 200:
            breaches = resp.json()
            return {
                "domain": domain,
                "breach_count": len(breaches),
                "breaches": [
                    {
                        "name": b.get("Name"),
                        "breach_date": b.get("BreachDate"),
                        "pwn_count": b.get("PwnCount"),
                        "data_classes": b.get("DataClasses", []),
                    }
                    for b in breaches
                ],
            }
        resp.raise_for_status()
        return {"domain": domain, "breaches": []}
    except Exception as e:
        return {"domain": domain, "error": str(e)}


def monitor_emails(emails: List[str]) -> List[dict]:
    """Bulk check multiple emails for breaches."""
    return [check_email(e) for e in emails]


def _risk_summary(breaches: list) -> str:
    all_classes = set()
    for b in breaches:
        all_classes.update(b.get("DataClasses", []))

    critical = {"Passwords", "Credit cards", "Social security numbers", "Bank account numbers"}
    high = {"Email addresses", "Phone numbers", "Physical addresses", "Dates of birth"}

    found_critical = all_classes & critical
    found_high = all_classes & high

    parts = []
    if found_critical:
        parts.append(f"CRITICAL data exposed: {', '.join(found_critical)}")
    if found_high:
        parts.append(f"Personal data: {', '.join(found_high)}")
    remaining = all_classes - critical - high
    if remaining:
        parts.append(f"Other: {', '.join(list(remaining)[:3])}")

    return " | ".join(parts) if parts else "Data types unknown"
