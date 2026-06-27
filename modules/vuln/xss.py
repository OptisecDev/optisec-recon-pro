import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlencode, urlparse, parse_qs
from config import DEFAULT_TIMEOUT

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


def _check_reflection(text: str, payload: str) -> bool:
    """Check if payload or a key portion is reflected."""
    tl = text.lower()
    pl = payload.lower()
    if pl in tl:
        return True
    # Check partial reflection of dangerous parts
    for frag in ["<script", "onerror=", "onload=", "alert(", "<svg", "<img"]:
        if frag in pl and frag in tl:
            return True
    return False


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
                if _check_reflection(r.text, payload):
                    findings.append({
                        "type": "XSS",
                        "severity": "High",
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"Payload reflected in GET response (HTTP {r.status_code})",
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
                    if _check_reflection(resp.text, payload):
                        findings.append({
                            "type": "XSS",
                            "severity": "High",
                            "url": form_url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": f"Payload reflected via {method.upper()} form submission (HTTP {resp.status_code})",
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
            if _check_reflection(r.text, payload):
                findings.append({
                    "type": "XSS",
                    "severity": "Medium",
                    "url": url,
                    "parameter": header,
                    "payload": payload,
                    "evidence": f"Payload reflected from {header} header (HTTP {r.status_code})",
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
