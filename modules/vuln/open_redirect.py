import requests
from urllib.parse import urlparse, parse_qs, urlencode
from config import DEFAULT_TIMEOUT
from modules.vuln._concurrency import run_concurrent_scan
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


def _test_param(session: requests.Session, parsed, params: dict, param: str) -> list:
    # Only the CONFIRMED entry (if any) or the last non-reporting verdict
    # tried for this param is kept — one row per param, not one per
    # payload, so retaining WAF_BLOCKED/etc. doesn't multiply findings.
    pending = None
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
            entry = {
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
            }
            if result.verdict == "ENDPOINT_INVALID":
                pending = entry  # path itself is unreachable, no point trying more payloads
                break
            if result.should_report:
                return [entry]
            pending = entry
        except Exception:
            continue
    return [pending] if pending is not None else []


def _scan_one_url(session: requests.Session, target_url: str) -> list:
    parsed = urlparse(target_url)
    params = parse_qs(parsed.query)

    redirect_params = [k for k in params if any(kw in k.lower() for kw in
                       ["redirect", "url", "next", "return", "goto", "dest", "destination",
                        "redir", "return_url", "returnurl", "forward", "target"])]
    if not redirect_params:
        redirect_params = list(params.keys())[:5]

    return run_concurrent_scan(redirect_params, lambda param: _test_param(session, parsed, params, param))


def scan_open_redirect(url: str, crawled_urls: list = None, crawled_forms: list = None) -> list:
    """`crawled_urls` — from modules.vuln.crawler.crawl(url) — lets the
    caller hand this scanner real query-string params discovered across
    every page reachable from `url`, not just `url` itself. Defaults to
    None so existing single-URL callers are unaffected. `crawled_forms` is
    accepted for interface parity with the other scan_*() functions but
    unused — open-redirect testing here only ever targets URL query
    params, never form fields."""
    session = requests.Session()
    session.headers["User-Agent"] = "OPTISEC-ReconPro/1.0 (Security Testing)"

    urls_to_test = [url] + [u for u in (crawled_urls or []) if u != url]
    findings = []
    seen = set()
    for target_url in urls_to_test:
        for f in _scan_one_url(session, target_url):
            key = (f["url"], f["parameter"])
            if key not in seen:
                seen.add(key)
                findings.append(f)
    return findings
