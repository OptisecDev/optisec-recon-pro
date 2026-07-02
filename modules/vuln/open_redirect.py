import requests
from urllib.parse import urlparse, parse_qs, urlencode
from config import DEFAULT_TIMEOUT
from modules.vuln.waf_aware_classifier import classify_signature_match

REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})

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
                # Only a Location actually pointing at our external marker is
                # real evidence of an open redirect — any 3xx with *some*
                # Location (even same-site, e.g. redirecting to /login) is
                # not, and was a false-positive source in the old check.
                matched_signal = loc if "evil.com" in loc else None
                result = classify_signature_match(
                    r.status_code, r.headers, r.text, matched_signal,
                    severity="Medium", signal_label="Open Redirect Location header",
                    expected_status_codes=REDIRECT_STATUS_CODES,
                )
                if result.verdict == "ENDPOINT_INVALID":
                    break  # path itself is unreachable, no point trying more payloads
                if result.should_report:
                    findings.append({
                        "type": "Open Redirect",
                        "severity": result.severity,
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"Redirect to: {loc} (status {r.status_code})",
                        "waf_detected": result.waf_detected,
                        "verdict": result.verdict,
                        "status_code": r.status_code,
                        "response_body": r.text[:3000],
                    })
                    break
            except Exception:
                continue

    return findings
