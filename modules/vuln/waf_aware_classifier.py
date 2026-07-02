"""WAF-aware classification of reflected XSS test responses.

Turns a raw HTTP response + payload into one of four verdicts so the XSS
scanner stops treating every reflection as an exploitable vulnerability:

  CONFIRMED        raw (unencoded) payload reflected, HTTP 200, no WAF seen
  WAF_BLOCKED       known WAF signature + a blocking status code
  ENDPOINT_INVALID  HTTP 404/400 — nothing was actually tested
  ENCODED_SAFE      payload present only in HTML-entity-encoded form

Only CONFIRMED sets should_report=True; the scanner should persist a
Finding only in that case.
"""

from dataclasses import dataclass
from html import escape
from typing import Optional

BLOCKING_STATUS_CODES = {403, 406, 429}
INVALID_STATUS_CODES = {404, 400}

# Signatures for common WAF/CDN vendors: response headers are the most
# reliable signal, "server" header tokens are a fallback, and block-page
# body text is the last resort (some WAFs strip identifying headers).
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status"],
        "server_tokens": ["cloudflare"],
        "body_markers": [
            "sorry, you have been blocked",
            "attention required! | cloudflare",
            "cloudflare ray id",
        ],
    },
    "Akamai": {
        "headers": ["akamai-grn"],
        "server_tokens": ["akamaighost"],
        "body_markers": [
            "akamai reference #",
        ],
    },
    "Imperva": {
        "headers": ["x-iinfo"],
        "server_tokens": ["incapsula"],
        "body_markers": [
            "incapsula incident id",
            "request unsuccessful. incapsula",
        ],
    },
    "AWS WAF": {
        "headers": ["x-amzn-waf-action"],
        "server_tokens": [],
        "body_markers": [
            "request blocked",
            "the request could not be satisfied",
            "request blocked aws waf",
        ],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id"],
        "server_tokens": ["sucuri/cloudproxy"],
        "body_markers": [
            "access denied - sucuri website firewall",
            "access denied sucuri",
            "sucuri website firewall - cloudproxy",
        ],
    },
    "F5 BIG-IP ASM": {
        "headers": ["x-wa-info"],
        "server_tokens": ["big-ip", "bigip"],
        "body_markers": [
            "the requested url was rejected",
            "please consult with your administrator",
        ],
    },
}


@dataclass
class ClassificationResult:
    verdict: str
    severity: Optional[str]
    should_report: bool
    waf_detected: Optional[str]
    reason: str


def detect_waf(headers: dict, body: str) -> Optional[str]:
    """Return the detected WAF/CDN vendor name, or None."""
    headers_lower = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    body_lower = (body or "").lower()

    for vendor, sig in WAF_SIGNATURES.items():
        if any(h in headers_lower for h in sig["headers"]):
            return vendor

    server = headers_lower.get("server", "")
    for vendor, sig in WAF_SIGNATURES.items():
        if any(tok in server for tok in sig.get("server_tokens", [])):
            return vendor

    for vendor, sig in WAF_SIGNATURES.items():
        if any(marker in body_lower for marker in sig.get("body_markers", [])):
            return vendor

    return None


def _reflected_raw(body: str, payload: str) -> bool:
    body_lower = (body or "").lower()
    payload_lower = (payload or "").lower()
    if payload_lower and payload_lower in body_lower:
        return True
    for frag in ("<script", "onerror=", "onload=", "<svg", "<img", "javascript:"):
        if frag in payload_lower and frag in body_lower:
            return True
    return False


def _reflected_encoded(body: str, payload: str) -> bool:
    body_lower = (body or "").lower()
    encoded = escape(payload or "", quote=True).lower()
    if encoded and encoded in body_lower:
        return True
    for raw_frag, enc_frag in (
        ("<", "&lt;"),
        (">", "&gt;"),
        ('"', "&quot;"),
        ("'", "&#x27;"),
        ("'", "&#39;"),
    ):
        if raw_frag in (payload or "") and enc_frag in body_lower:
            return True
    return False


def classify(status_code: int, headers: dict, body: str, payload: str) -> ClassificationResult:
    waf_vendor = detect_waf(headers, body)

    if status_code in INVALID_STATUS_CODES:
        return ClassificationResult(
            verdict="ENDPOINT_INVALID",
            severity=None,
            should_report=False,
            waf_detected=waf_vendor,
            reason=f"HTTP {status_code} — endpoint not reachable/valid, not a real test",
        )

    if status_code in BLOCKING_STATUS_CODES and waf_vendor:
        return ClassificationResult(
            verdict="WAF_BLOCKED",
            severity="Medium",
            should_report=False,
            waf_detected=waf_vendor,
            reason=f"Blocked by {waf_vendor} (HTTP {status_code})",
        )

    raw = _reflected_raw(body, payload)
    if raw and status_code == 200 and not waf_vendor:
        return ClassificationResult(
            verdict="CONFIRMED",
            severity="High",
            should_report=True,
            waf_detected=None,
            reason="Raw payload reflected unencoded, HTTP 200, no WAF detected",
        )

    encoded = _reflected_encoded(body, payload)
    if encoded and not raw:
        return ClassificationResult(
            verdict="ENCODED_SAFE",
            severity=None,
            should_report=False,
            waf_detected=waf_vendor,
            reason="Payload present but HTML-entity encoded — not exploitable",
        )

    return ClassificationResult(
        verdict="INCONCLUSIVE",
        severity=None,
        should_report=False,
        waf_detected=waf_vendor,
        reason="No raw reflection, encoding, WAF block, or invalid-endpoint signal detected",
    )


def classify_response(response, payload: str) -> ClassificationResult:
    """Convenience wrapper around classify() for a requests/httpx Response object."""
    status_code = getattr(response, "status_code", 0)
    headers = dict(getattr(response, "headers", {}) or {})
    body = getattr(response, "text", "") or ""
    return classify(status_code, headers, body, payload)
