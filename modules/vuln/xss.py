import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlencode, urlparse, parse_qs
from config import DEFAULT_TIMEOUT
from modules.vuln._concurrency import run_concurrent_scan
from modules.vuln.waf_aware_classifier import classify

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    '"><img src=x onerror=alert(1)>',
    "<body onload=alert(1)>",
    "<script>alert('xss')</script>",
    '"><svg/onload=alert(1)>',
    "';alert(1)//",
]

# Lightweight markers to detect partial reflection without full payload
_MARKERS = ["optisecxss49", "xsstestopti"]


def _test_url_param(session: requests.Session, parsed, params: dict, param: str) -> list:
    # Only the CONFIRMED entry (if any) or the last non-reporting verdict
    # tried for this param is kept — one row per param, not one per
    # payload, so retaining WAF_BLOCKED/etc. doesn't multiply findings.
    pending = None
    for payload in XSS_PAYLOADS:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[param] = payload
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
        try:
            r = session.get(test_url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            result = classify(r.status_code, r.headers, r.text, payload)
            entry = {
                "type": "XSS",
                "severity": result.severity,
                "url": test_url,
                "parameter": param,
                "payload": payload,
                "evidence": f"{result.reason} (HTTP {r.status_code})",
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


def _scan_url_params(session: requests.Session, url: str) -> list:
    """Test XSS via URL query parameters (each param tested concurrently)."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        # No real query string to test — probe with 2 representative
        # guessed names rather than 4, since none of these correspond to an
        # actual endpoint parameter anyway (this is a heuristic guess for a
        # bare-domain scan, not a real surface); halves the wasted request
        # volume on the most common scan shape.
        params = {"q": ["test"], "id": ["1"]}

    return run_concurrent_scan(params.keys(), lambda param: _test_url_param(session, parsed, params, param))


def _test_form_param(session: requests.Session, form_url: str, method: str, inputs: dict, param: str) -> list:
    pending = None
    for payload in XSS_PAYLOADS[:5]:  # fewer payloads for form scanning
        test_data = dict(inputs)
        test_data[param] = payload
        try:
            if method == "post":
                resp = session.post(form_url, data=test_data, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            else:
                resp = session.get(form_url, params=test_data, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            result = classify(resp.status_code, resp.headers, resp.text, payload)
            entry = {
                "type": "XSS",
                "severity": result.severity,
                "url": form_url,
                "parameter": param,
                "payload": payload,
                "evidence": f"{result.reason} via {method.upper()} form submission (HTTP {resp.status_code})",
                "waf_detected": result.waf_detected,
                "verdict": result.verdict,
                "status_code": resp.status_code,
                "response_body": resp.text[:3000],
            }
            if result.verdict == "ENDPOINT_INVALID":
                pending = entry
                break
            if result.should_report:
                return [entry]
            pending = entry
        except Exception:
            continue
    return [pending] if pending is not None else []


def _scan_forms(session: requests.Session, base_url: str, forms_override: list = None) -> list:
    """Test XSS via POST/GET form submission (each form field tested
    concurrently). `forms_override` — a list of (form_url, method, inputs)
    from a prior crawl() across every discovered page — is used when given;
    otherwise falls back to fetching just `base_url` and parsing its own
    forms (original single-page behavior, kept for backward compatibility
    and for callers that never crawl)."""
    if forms_override is not None:
        form_specs = forms_override[:20]
    else:
        try:
            r = session.get(base_url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            soup = BeautifulSoup(r.text, "html.parser")
        except Exception:
            return []

        form_specs = []
        for form in soup.find_all("form")[:5]:  # limit to 5 forms
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            form_url = urljoin(base_url, action) if action else base_url

            # Collect all text/search/email inputs
            inputs = {}
            for inp in form.find_all(["input", "textarea"]):
                name = inp.get("name", "")
                if not name:
                    continue
                itype = inp.get("type", "text").lower()
                if itype in ("text", "search", "email", "url", "tel", "textarea", "hidden", ""):
                    inputs[name] = inp.get("value", "test")

            if inputs:
                form_specs.append((form_url, method, inputs))

    tasks = []
    for form_url, method, inputs in form_specs:
        for param in inputs:
            tasks.append((form_url, method, inputs, param))

    return run_concurrent_scan(tasks, lambda t: _test_form_param(session, *t))


def _test_header(session: requests.Session, url: str, payload: str, header: str, value: str) -> list:
    try:
        r = session.get(url, headers={header: value}, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        result = classify(r.status_code, r.headers, r.text, payload)
        return [{
            "type": "XSS",
            "severity": result.severity,
            "url": url,
            "parameter": header,
            "payload": payload,
            "evidence": f"{result.reason} from {header} header (HTTP {r.status_code})",
            "waf_detected": result.waf_detected,
            "verdict": result.verdict,
            "status_code": r.status_code,
            "response_body": r.text[:3000],
        }]
    except Exception:
        return []


def _scan_headers(session: requests.Session, url: str) -> list:
    """Test XSS via HTTP headers that may be reflected (User-Agent, Referer, X-Forwarded-For)."""
    payload = "<script>alert(1)</script>"
    headers_to_test = {
        "User-Agent": payload,
        "Referer": f"{url}?x={payload}",
        "X-Forwarded-For": payload,
    }
    return run_concurrent_scan(
        headers_to_test.items(),
        lambda item: _test_header(session, url, payload, item[0], item[1]),
    )


def scan_xss(url: str, crawled_urls: list = None, crawled_forms: list = None) -> list:
    """`crawled_urls`/`crawled_forms` — from modules.vuln.crawler.crawl(url)
    — let the caller hand this scanner real attack surface discovered
    across every page reachable from `url`, not just `url` itself. Both
    default to None so existing single-URL callers are unaffected."""
    session = requests.Session()
    session.headers["User-Agent"] = "OPTISEC-ReconPro/1.0 (Security Testing)"

    findings = []
    seen_params = set()

    urls_to_test = [url] + [u for u in (crawled_urls or []) if u != url]
    for target_url in urls_to_test:
        for f in _scan_url_params(session, target_url):
            key = (f["url"], f["parameter"])
            if key not in seen_params:
                seen_params.add(key)
                findings.append(f)

    forms_override = [(cf.url, cf.method, cf.inputs) for cf in crawled_forms] if crawled_forms else None
    for f in _scan_forms(session, url, forms_override=forms_override):
        key = (f["url"], f["parameter"])
        if key not in seen_params:
            seen_params.add(key)
            findings.append(f)

    for f in _scan_headers(session, url):
        key = (f["url"], f["parameter"])
        if key not in seen_params:
            seen_params.add(key)
            findings.append(f)

    return findings
