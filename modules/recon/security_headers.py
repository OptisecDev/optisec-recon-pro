"""HTTP Security Headers Analysis."""

import requests
from config import DEFAULT_TIMEOUT

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "short": "HSTS",
        "importance": "critical",
        "description": "Forces HTTPS connections",
        "recommendation": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "short": "CSP",
        "importance": "critical",
        "description": "Prevents XSS and data injection attacks",
        "recommendation": "Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    "X-Frame-Options": {
        "short": "XFO",
        "importance": "high",
        "description": "Prevents clickjacking attacks",
        "recommendation": "X-Frame-Options: SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "short": "XCTO",
        "importance": "medium",
        "description": "Prevents MIME-type sniffing",
        "recommendation": "X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "short": "RP",
        "importance": "medium",
        "description": "Controls referrer information",
        "recommendation": "Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "short": "PP",
        "importance": "medium",
        "description": "Controls browser feature access",
        "recommendation": "Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
    "X-XSS-Protection": {
        "short": "XXP",
        "importance": "low",
        "description": "Legacy XSS protection (deprecated in modern browsers)",
        "recommendation": "X-XSS-Protection: 1; mode=block",
    },
    "Cache-Control": {
        "short": "CC",
        "importance": "low",
        "description": "Controls caching behavior",
        "recommendation": "Cache-Control: no-store for sensitive pages",
    },
    "Cross-Origin-Opener-Policy": {
        "short": "COOP",
        "importance": "medium",
        "description": "Isolates browsing context",
        "recommendation": "Cross-Origin-Opener-Policy: same-origin",
    },
    "Cross-Origin-Resource-Policy": {
        "short": "CORP",
        "importance": "medium",
        "description": "Controls cross-origin resource loading",
        "recommendation": "Cross-Origin-Resource-Policy: same-origin",
    },
}

DANGEROUS_HEADERS = {
    "Server": "Reveals server software — enables targeted exploits",
    "X-Powered-By": "Reveals backend technology stack",
    "X-AspNet-Version": "Reveals .NET version",
    "X-AspNetMvc-Version": "Reveals MVC version",
}


def check_security_headers(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    try:
        resp = requests.get(
            url, timeout=DEFAULT_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; OPTISEC/2.0 SecurityScanner)"},
            verify=False,
        )
        status_code = resp.status_code
        headers = {k.lower(): v for k, v in resp.headers.items()}
    except Exception as e:
        return {"url": url, "error": str(e)}

    present = {}
    missing = {}

    for header, meta in SECURITY_HEADERS.items():
        value = headers.get(header.lower())
        if value:
            present[header] = {
                **meta,
                "value": value,
                "status": "present",
            }
        else:
            missing[header] = {
                **meta,
                "status": "missing",
            }

    # Dangerous headers
    exposed = {}
    for header, risk in DANGEROUS_HEADERS.items():
        val = headers.get(header.lower())
        if val:
            exposed[header] = {"value": val, "risk": risk}

    score = _calc_security_score(present, missing)

    return {
        "url": url,
        "status_code": status_code,
        "final_url": resp.url,
        "security_score": score,
        "grade": _grade(score),
        "present_headers": present,
        "missing_headers": missing,
        "exposed_info_headers": exposed,
        "summary": {
            "total_checked": len(SECURITY_HEADERS),
            "present": len(present),
            "missing": len(missing),
            "info_exposed": len(exposed),
        },
        "risk_score": 100 - score,
        "risk_label": "HIGH" if score < 40 else "MEDIUM" if score < 70 else "LOW",
    }


def _calc_security_score(present: dict, missing: dict) -> int:
    weights = {"critical": 30, "high": 20, "medium": 10, "low": 5}
    total_possible = sum(weights.get(meta["importance"], 5) for meta in SECURITY_HEADERS.values())
    earned = sum(weights.get(meta["importance"], 5) for meta in present.values())
    return int((earned / total_possible) * 100)


def _grade(score: int) -> str:
    if score >= 90:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 70:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"
