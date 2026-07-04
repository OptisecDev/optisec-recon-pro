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

# Generic network-error strings that plenty of ordinary pages emit on their
# own upstream failures (a flaky third-party API, their own DB, ...) with no
# relation to SSRF. Trusting a match on one of these requires corroborating
# evidence: a body that actually looks like a real internal-service response
# (AWS instance-metadata's line-per-key listing), or a real timing gap
# between the payload request and a same-endpoint baseline request.
SSRF_WEAK_INDICATORS = {"Connection refused", "Connection timed out", "Name or service not known"}

# A real http://169.254.169.254/latest/meta-data/ response lists metadata
# category names one per line — seeing two or more of these as whole lines is
# real structure; a lone "instance-id" substring inside prose text is not.
_AWS_METADATA_KEYS = {
    "ami-id", "ami-launch-index", "ami-manifest-path", "instance-id",
    "instance-type", "instance-action", "local-hostname", "public-hostname",
    "security-groups", "local-ipv4", "public-ipv4", "hostname",
}

# Minimum timing differential (seconds) between the baseline and payload
# requests before a generic network-error string counts as SSRF evidence.
SSRF_TIMING_THRESHOLD_SECONDS = 3.0


def _looks_like_aws_metadata_body(body: str) -> bool:
    lines = {line.strip().lower() for line in (body or "").splitlines()}
    return len(lines & _AWS_METADATA_KEYS) >= 2


def _elapsed_seconds(response):
    total_seconds = getattr(getattr(response, "elapsed", None), "total_seconds", None)
    return total_seconds() if callable(total_seconds) else None


def _ssrf_indicator_confirmed(body: str, matched_indicator: str, baseline_elapsed, payload_elapsed) -> bool:
    """Weak/generic network-error indicators need real corroborating evidence
    before being trusted; the other, more specific indicators are trusted
    as-is (unchanged behavior)."""
    if matched_indicator not in SSRF_WEAK_INDICATORS:
        return True
    if _looks_like_aws_metadata_body(body):
        return True
    if baseline_elapsed is not None and payload_elapsed is not None:
        if abs(payload_elapsed - baseline_elapsed) >= SSRF_TIMING_THRESHOLD_SECONDS:
            return True
    return False


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

        # Baseline (unmodified) request for this param, used to detect a real
        # timing differential against SSRF payloads further down.
        baseline_elapsed = None
        try:
            baseline_params = {k: v[0] for k, v in params.items()}
            baseline_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(baseline_params)}"
            baseline_resp = session.get(baseline_url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            baseline_elapsed = _elapsed_seconds(baseline_resp)
        except Exception:
            baseline_elapsed = None

        for payload in SSRF_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
            try:
                r = session.get(test_url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                body_lower = r.text.lower()
                matched_indicator = next((ind for ind in SSRF_INDICATORS if ind.lower() in body_lower), None)
                if matched_indicator and not _ssrf_indicator_confirmed(
                    r.text, matched_indicator, baseline_elapsed, _elapsed_seconds(r)
                ):
                    matched_indicator = None
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
