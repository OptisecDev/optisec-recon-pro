import requests
from urllib.parse import urlparse, parse_qs, urlencode
from config import DEFAULT_TIMEOUT

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "//evil.com/",
    "https://evil.com/",
    "http://evil.com",
    "/\\evil.com",
    "/%5C/evil.com",
    "https:evil.com",
    "//evil%2Ecom",
    "///evil.com",
    "////evil.com",
]


def scan_open_redirect(url: str) -> list:
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    redirect_params = [k for k in params if any(kw in k.lower() for kw in
                       ["redirect", "url", "next", "return", "goto", "dest", "destination",
                        "redir", "return_url", "returnurl", "forward", "target"])]
    if not redirect_params:
        redirect_params = list(params.keys())[:5]

    session = requests.Session()
    session.headers["User-Agent"] = "OPTISEC-ReconPro/1.0 (Security Testing)"

    for param in redirect_params:
        for payload in REDIRECT_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
            try:
                r = session.get(test_url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                loc = r.headers.get("Location", "")
                if "evil.com" in loc or (r.status_code in (301, 302, 303, 307, 308) and loc):
                    findings.append({
                        "type": "Open Redirect",
                        "severity": "Medium",
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"Redirect to: {loc} (status {r.status_code})",
                    })
                    break
            except Exception:
                continue

    return findings
