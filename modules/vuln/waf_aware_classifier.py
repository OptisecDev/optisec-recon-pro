"""WAF-aware classification of vulnerability-scan test responses.

Turns a raw HTTP response (+ payload/signal) into a verdict so scanners stop
treating every reflection/error/timing signal as an exploitable
vulnerability outright. Two families of checks share the same WAF-detection
core (detect_waf/WAF_SIGNATURES/BLOCKING_STATUS_CODES/INVALID_STATUS_CODES):

XSS reflection — classify()/classify_response(), five verdicts:
  CONFIRMED        raw payload reflected in a genuinely executable HTML
                   context (real <script>/event-handler sink, verified by
                   parsing the response — not just a body-wide substring
                   match), HTTP 200, no WAF seen
  POSSIBLE          raw payload reflected verbatim, but it landed somewhere
                   a browser would not execute it (inert attribute text,
                   HTML comment, a JSON response body, ...) — needs manual
                   review, never auto-reported
  WAF_BLOCKED       known WAF signature + a blocking status code
  ENDPOINT_INVALID  HTTP 404/400 — nothing was actually tested
  ENCODED_SAFE      payload present only in HTML-entity-encoded form

SQLi (error-based/blind) — classify_error_signature()/classify_blind_signal(),
same WAF_BLOCKED/ENDPOINT_INVALID verdicts, but no ENCODED_SAFE equivalent
(there's no "encoded" form of a DB error string or a timing delay) — an
unconfirmed signal falls through to INCONCLUSIVE instead.

GraphQL introspection — classify_graphql_introspection(), same
WAF_BLOCKED/ENDPOINT_INVALID verdicts plus one verdict unique to this
family: INTROSPECTION_DISABLED (endpoint confirmed to be GraphQL, but it
rejected the introspection query — a negative-but-informative result, not
an error). CONFIRMED here means introspection is enabled, not that a
traditional injection payload was reflected.

Only CONFIRMED sets should_report=True; scanners should persist a Finding
only in that case.
"""

import json
from dataclasses import dataclass
from html import escape
from typing import Optional

from bs4 import BeautifulSoup

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
    """`waf_detected` is NOT a boolean flag and NULL/None is an expected,
    intentional value for most verdicts — it is NOT a bug or missing data.
    Semantics per verdict (confirmed against the code below on 2026-07-04,
    see SESSION.md "Design Note — waf_detected/verdict" for the full
    investigation that established this):

      CONFIRMED
        waf_detected is ALWAYS forced to None, unconditionally. A CONFIRMED
        verdict means the technical signal itself (raw XSS reflection
        verified to sit in an executable HTML context, DB error string,
        blind boolean/timing differential, off-site redirect Location)
        proved the vulnerability directly — it has nothing to do with WAF
        detection, so there is nothing WAF-related to record here.

      WAF_BLOCKED
        waf_detected is ALWAYS a vendor name, NEVER None — reaching this
        verdict requires detect_waf() to have already matched a vendor
        (see the `waf_vendor` truthiness check gating this branch).

      POSSIBLE / ENDPOINT_INVALID / ENCODED_SAFE / INCONCLUSIVE
        waf_detected is whatever detect_waf() returned for that response:
        a vendor name if a known WAF/CDN signature happened to be present,
        or None if it simply didn't match any signature in WAF_SIGNATURES
        (the common case for targets with no recognized WAF). None here
        means "no WAF signature matched", not "detection failed".

    Only CONFIRMED sets should_report=True. POSSIBLE is a raw-text match
    that failed context verification — it is persisted for analyst review
    (like every other verdict) but is never auto-reported as confirmed.
    """
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
    """True only if the exact injected payload appears in the response.

    Previously this also matched generic tag fragments (``<script``,
    ``onerror=``, ``<img``, etc.) anywhere in the body if the payload
    happened to contain them too — but those fragments routinely occur in a
    target's own legitimate markup/CSP, unrelated to anything reflected from
    the injected payload. That produced false CONFIRMED verdicts against
    pages that never echoed the payload at all (see reports/bounty_scan_*
    findings against verisign.com — every fragment-only "reflection" turned
    out to be the site's own <script>/<img> tags, not the payload).
    """
    body_lower = (body or "").lower()
    payload_lower = (payload or "").lower()
    return bool(payload_lower) and payload_lower in body_lower


def _looks_like_json_response(headers: dict, body: str) -> bool:
    """True if this response is a JSON document rather than an HTML page.

    html.parser scans the byte stream for `<tag>` patterns with no idea
    that it is actually looking at a JSON string value — so a payload like
    ``<script>alert(1)</script>`` sitting inside a JSON field (e.g.
    ``{"query": "<script>alert(1)</script>"}``) would otherwise get
    "parsed" into a real-looking <script> element and wrongly pass the
    executable-context check below. A JSON response never gets rendered as
    HTML by a browser on its own, so raw reflection here can never be
    CONFIRMED by this signal alone.
    """
    for k, v in (headers or {}).items():
        if str(k).lower() == "content-type" and "json" in str(v).lower():
            return True
    stripped = (body or "").strip()
    if stripped[:1] in ("{", "["):
        try:
            json.loads(stripped)
            return True
        except (TypeError, ValueError):
            return False
    return False


def _fragment_correlates(found: str, payload: str) -> bool:
    """True if `found` (real script text / event-handler attribute value
    pulled from the parsed DOM) is meaningfully the same content as the
    injected `payload` — either direction, since a payload that creates a
    new tag embeds a short fragment (e.g. attribute value "alert(1)") as a
    substring of the full payload, while a payload that breaks out of an
    existing inline <script> string (e.g. ``';alert(1)//``) ends up fully
    embedded inside that script's (longer) text content instead."""
    found = (found or "").strip().lower()
    payload = (payload or "").lower()
    if len(found) < 3:
        return False
    return found in payload or payload in found


def _raw_reflection_is_executable(status_code: int, headers: dict, body: str, payload: str) -> bool:
    """True only if the raw-reflected payload actually landed somewhere a
    browser would execute it, verified by parsing the response — not just
    because the exact payload string happens to appear anywhere in the raw
    body text.

    Guards against the false-CONFIRMED class of bug where a payload was
    merely echoed back with zero relation to any real sink: inert text
    inside a quoted HTML attribute value, inside an HTML comment, or inside
    a JSON API response body. Real browsers never execute any of those, so
    a raw substring match alone was never sufficient evidence.
    """
    if not payload:
        return False
    if _looks_like_json_response(headers, body):
        return False

    try:
        soup = BeautifulSoup(body or "", "html.parser")
    except Exception:
        return False

    for script in soup.find_all("script"):
        if _fragment_correlates(script.get_text(), payload):
            return True

    for tag in soup.find_all(True):
        for attr, value in tag.attrs.items():
            if not str(attr).lower().startswith("on"):
                continue
            value_str = value if isinstance(value, str) else " ".join(value or [])
            if _fragment_correlates(value_str, payload):
                return True
            # The attribute existing at all with the payload as its exact
            # value (parser may leave multi-token payloads unsplit in some
            # malformed-HTML edge cases) is also sufficient.
            if _fragment_correlates(payload, value_str):
                return True

        href = tag.attrs.get("src") or tag.attrs.get("href") or ""
        href_str = href if isinstance(href, str) else " ".join(href or [])
        if href_str.lower().startswith("javascript:") and _fragment_correlates(href_str, payload):
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
        if _raw_reflection_is_executable(status_code, headers, body, payload):
            return ClassificationResult(
                verdict="CONFIRMED",
                severity="High",
                should_report=True,
                # Intentionally None, not a bug: CONFIRMED already means "no
                # WAF was in the way" (see `not waf_vendor` above) — see
                # ClassificationResult docstring for the full verdict/None
                # table.
                waf_detected=None,
                reason="Raw payload reflected in an executable HTML context (real <script>/event-handler sink), HTTP 200, no WAF detected",
            )
        return ClassificationResult(
            verdict="POSSIBLE",
            severity="Medium",
            should_report=False,
            waf_detected=waf_vendor,
            reason="Raw payload reflected verbatim, but not in a verified executable context (may be inert attribute text, a comment, or a JSON body) — needs manual review",
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


def classify_signature_match(
    status_code: int, headers: dict, body: str, matched_signal: Optional[str],
    *, severity: str = "Critical", signal_label: str = "signature",
    expected_status_codes=frozenset({200}),
) -> ClassificationResult:
    """Classify a single-response, signature-in-<something> test — the
    shared shape behind SQLi error-based detection, LFI (file-content
    indicators), SSRF (internal-service response indicators), and open
    redirect (Location header pointing off-site): a request was made, and
    the caller already checked whether a known string shows up wherever the
    signal lives for that vuln type. `severity`/`signal_label` let each vuln
    type keep its own wording and severity; `expected_status_codes` lets it
    define what "the test actually happened as expected" means — 200 for a
    reflected body, 3xx for a followed redirect — while sharing the same
    WAF/validity gating logic."""
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

    if matched_signal and status_code in expected_status_codes and not waf_vendor:
        return ClassificationResult(
            verdict="CONFIRMED",
            severity=severity,
            should_report=True,
            # Intentionally None, not a bug — see ClassificationResult docstring.
            waf_detected=None,
            reason=f"{signal_label} detected: '{matched_signal}'",
        )

    return ClassificationResult(
        verdict="INCONCLUSIVE",
        severity=None,
        should_report=False,
        waf_detected=waf_vendor,
        reason=f"No conclusive {signal_label.lower()}, WAF block, or invalid-endpoint signal detected",
    )


def classify_error_signature(status_code: int, headers: dict, body: str, matched_error: Optional[str]) -> ClassificationResult:
    """Classify an error-based SQLi test: a DB error string was (or wasn't)
    found in the response body of a single request. Thin wrapper over
    classify_signature_match() kept for backward compatibility."""
    return classify_signature_match(
        status_code, headers, body, matched_error,
        severity="Critical", signal_label="SQL error signature",
    )


def classify_blind_signal(
    status_code_a: int, headers_a: dict, body_a: str,
    status_code_b: int, headers_b: dict, body_b: str,
    signal_detected: bool, technique: str,
) -> ClassificationResult:
    """Classify a boolean- or time-based blind SQLi test: `signal_detected`
    is the caller's differential (length/status diff, or timing delta past
    threshold) between two requests (true/false or normal/delayed). Both
    responses are checked for WAF/invalid-endpoint noise before trusting the
    differential — a WAF challenge page can easily produce a content-length
    or timing difference that has nothing to do with SQLi.

    Note: ENDPOINT_INVALID requires *both* responses to be 404/400 — a
    status-code split (e.g. true=200/false=404) caused by the injected
    condition is exactly the boolean-based signal being tested for, not
    proof the endpoint doesn't exist."""
    if status_code_a in INVALID_STATUS_CODES and status_code_b in INVALID_STATUS_CODES:
        return ClassificationResult(
            verdict="ENDPOINT_INVALID",
            severity=None,
            should_report=False,
            waf_detected=detect_waf(headers_a, body_a) or detect_waf(headers_b, body_b),
            reason=f"HTTP {status_code_a}/{status_code_b} on both requests — endpoint not reachable/valid, not a real test",
        )

    waf_vendor = detect_waf(headers_a, body_a) or detect_waf(headers_b, body_b)
    if waf_vendor and (status_code_a in BLOCKING_STATUS_CODES or status_code_b in BLOCKING_STATUS_CODES):
        return ClassificationResult(
            verdict="WAF_BLOCKED",
            severity="Medium",
            should_report=False,
            waf_detected=waf_vendor,
            reason=f"Blocked by {waf_vendor} during {technique} probe",
        )

    if signal_detected and not waf_vendor:
        return ClassificationResult(
            verdict="CONFIRMED",
            severity="Critical",
            should_report=True,
            # Intentionally None, not a bug — see ClassificationResult docstring.
            waf_detected=None,
            reason=f"{technique} confirmed",
        )

    return ClassificationResult(
        verdict="INCONCLUSIVE",
        severity=None,
        should_report=False,
        waf_detected=waf_vendor,
        reason=f"No conclusive {technique} signal after WAF/validity checks",
    )


# GraphQL error messages that specifically mean "this is a real GraphQL
# endpoint, and it deliberately rejected the introspection query" — as
# opposed to a generic resolver error, which says nothing about
# introspection either way and must fall through to INCONCLUSIVE instead.
_INTROSPECTION_DISABLED_MARKERS = (
    "introspection is not allowed",
    "introspection is disabled",
    "graphql introspection is disabled",
    "introspection query is not allowed",
    'cannot query field "__schema"',
    'cannot query field "__type"',
    "persisted queries only",
)


def _parse_json_object(body: str) -> Optional[dict]:
    try:
        parsed = json.loads(body or "")
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _introspection_schema_present(parsed: Optional[dict]) -> bool:
    """True only if a `__schema` object with real type/query info came back
    — not just the bare key, which a non-GraphQL JSON API could echo back
    verbatim from a reflected request body."""
    if not parsed:
        return False
    schema = (parsed.get("data") or {}).get("__schema") if isinstance(parsed.get("data"), dict) else None
    return isinstance(schema, dict) and bool(schema.get("types") or schema.get("queryType"))


def _introspection_explicitly_disabled(parsed: Optional[dict]) -> bool:
    if not parsed or not isinstance(parsed.get("errors"), list):
        return False
    messages = " ".join(
        str(err.get("message", "")) for err in parsed["errors"] if isinstance(err, dict)
    ).lower()
    return any(marker in messages for marker in _INTROSPECTION_DISABLED_MARKERS)


def classify_graphql_introspection(status_code: int, headers: dict, body: str) -> ClassificationResult:
    """Classify a single introspection-query response (`{"query": "{
    __schema { ... } }"}`) into whether the target endpoint is (a) not
    GraphQL / not reachable, (b) WAF-blocked, (c) real GraphQL with
    introspection deliberately disabled, or (d) real GraphQL with
    introspection enabled (should_report=True — this is the reportable
    finding: production GraphQL endpoints should normally have
    introspection turned off)."""
    waf_vendor = detect_waf(headers, body)

    if status_code in INVALID_STATUS_CODES:
        return ClassificationResult(
            verdict="ENDPOINT_INVALID",
            severity=None,
            should_report=False,
            waf_detected=waf_vendor,
            reason=f"HTTP {status_code} — no GraphQL endpoint at this path",
        )

    if status_code in BLOCKING_STATUS_CODES and waf_vendor:
        return ClassificationResult(
            verdict="WAF_BLOCKED",
            severity="Medium",
            should_report=False,
            waf_detected=waf_vendor,
            reason=f"Blocked by {waf_vendor} (HTTP {status_code})",
        )

    parsed = _parse_json_object(body)

    if status_code == 200 and not waf_vendor and _introspection_schema_present(parsed):
        return ClassificationResult(
            verdict="CONFIRMED",
            severity="Medium",
            should_report=True,
            # Intentionally None, not a bug — see ClassificationResult docstring.
            waf_detected=None,
            reason="GraphQL introspection enabled — __schema query returned live type information",
        )

    if _introspection_explicitly_disabled(parsed):
        return ClassificationResult(
            verdict="INTROSPECTION_DISABLED",
            severity=None,
            should_report=False,
            waf_detected=waf_vendor,
            reason="GraphQL endpoint confirmed present, but it rejected the introspection query",
        )

    return ClassificationResult(
        verdict="INCONCLUSIVE",
        severity=None,
        should_report=False,
        waf_detected=waf_vendor,
        reason="Response does not look like a GraphQL introspection result",
    )
