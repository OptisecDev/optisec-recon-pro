"""
Tests for WAF-aware vulnerability classification
(modules/vuln/waf_aware_classifier.py).

Covers the XSS reflection verdicts — CONFIRMED, WAF_BLOCKED,
ENDPOINT_INVALID, ENCODED_SAFE — plus the INCONCLUSIVE safety-net fallback,
and the SQLi error-based/blind classification functions that share the same
WAF-detection core. No real network calls: responses are built via
httpx.MockTransport, mirroring the project's existing "never hit real APIs
in tests" convention (see tests/test_darkweb_monitor.py).
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
import pytest

from modules.vuln.waf_aware_classifier import (
    classify,
    classify_response,
    classify_error_signature,
    classify_blind_signal,
    classify_signature_match,
    classify_graphql_introspection,
    detect_waf,
)

PAYLOAD = "<script>alert(1)</script>"


def _mock_response(status_code=200, headers=None, body="", url="https://example.com/search?q=test"):
    """Build a real httpx.Response via MockTransport — no network I/O."""
    headers = headers or {}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, headers=headers, text=body)

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport) as client:
        return client.get(url)


class _FakeRequestsResponse:
    """Duck-typed stand-in for requests.Response (what xss.py actually uses)."""

    def __init__(self, status_code, headers, text):
        self.status_code = status_code
        self.headers = headers
        self.text = text


# ── CONFIRMED ─────────────────────────────────────────────────────────────

def test_confirmed_raw_reflection_no_waf():
    body = f"<html><body>search results for {PAYLOAD}</body></html>"
    resp = _mock_response(200, {}, body)
    result = classify_response(resp, PAYLOAD)

    assert result.verdict == "CONFIRMED"
    assert result.severity == "High"
    assert result.should_report is True
    assert result.waf_detected is None


def test_confirmed_partial_fragment_reflection():
    body = "<html><body><img src=x onerror=alert(1)></body></html>"
    resp = _mock_response(200, {}, body)
    result = classify(resp.status_code, resp.headers, resp.text, "<img src=x onerror=alert(1)>")

    assert result.verdict == "CONFIRMED"
    assert result.should_report is True


def test_confirmed_works_with_requests_style_response():
    """classify_response() must duck-type against requests.Response too, not just httpx."""
    resp = _FakeRequestsResponse(200, {}, f"echo: {PAYLOAD}")
    result = classify_response(resp, PAYLOAD)

    assert result.verdict == "CONFIRMED"
    assert result.should_report is True


def test_not_confirmed_when_waf_present_even_if_raw_reflected():
    """Raw reflection + HTTP 200 but a WAF header is present → must NOT be CONFIRMED."""
    body = f"<html><body>{PAYLOAD}</body></html>"
    resp = _mock_response(200, {"cf-ray": "abc123-DFW"}, body)
    result = classify_response(resp, PAYLOAD)

    assert result.verdict != "CONFIRMED"
    assert result.should_report is False
    assert result.waf_detected == "Cloudflare"


# ── WAF_BLOCKED ───────────────────────────────────────────────────────────

WAF_BLOCK_CASES = [
    ("Cloudflare", {"cf-ray": "abc123-DFW"}, "Sorry, you have been blocked"),
    ("Akamai", {"akamai-grn": "0.abcdefgh.1"}, "Access Denied - reference #18.abc"),
    ("Imperva", {"x-iinfo": "1-abc-def"}, "Incapsula incident ID: 123-456"),
    ("AWS WAF", {"x-amzn-waf-action": "block"}, "Request blocked AWS WAF"),
    ("Sucuri", {"x-sucuri-id": "12345"}, "Access Denied - Sucuri Website Firewall"),
    ("F5 BIG-IP ASM", {"x-wa-info": "1"}, "The requested URL was rejected. Please consult with your administrator."),
]


@pytest.mark.parametrize("status_code", [403, 406, 429])
@pytest.mark.parametrize("vendor,headers,body", WAF_BLOCK_CASES)
def test_waf_blocked_all_vendors_all_blocking_statuses(vendor, headers, body, status_code):
    resp = _mock_response(status_code, headers, body)
    result = classify_response(resp, PAYLOAD)

    assert result.verdict == "WAF_BLOCKED"
    assert result.severity == "Medium"
    assert result.should_report is False
    assert result.waf_detected == vendor


def test_waf_blocked_via_body_marker_only_no_header():
    resp = _mock_response(403, {}, "Access denied Sucuri Website Firewall - CloudProxy")
    result = classify_response(resp, PAYLOAD)

    assert result.verdict == "WAF_BLOCKED"
    assert result.waf_detected == "Sucuri"


def test_waf_blocked_via_server_header_token():
    resp = _mock_response(403, {"server": "Incapsula"}, "blocked")
    result = classify_response(resp, PAYLOAD)

    assert result.verdict == "WAF_BLOCKED"
    assert result.waf_detected == "Imperva"


def test_blocking_status_without_known_signature_is_not_waf_blocked():
    """A 403 with no recognizable WAF fingerprint must not be mislabeled."""
    resp = _mock_response(403, {}, "403 Forbidden")
    result = classify_response(resp, PAYLOAD)

    assert result.verdict != "WAF_BLOCKED"
    assert result.should_report is False


# ── ENDPOINT_INVALID ──────────────────────────────────────────────────────

@pytest.mark.parametrize("status_code", [404, 400])
def test_endpoint_invalid(status_code):
    resp = _mock_response(status_code, {}, "Not Found")
    result = classify_response(resp, PAYLOAD)

    assert result.verdict == "ENDPOINT_INVALID"
    assert result.severity is None
    assert result.should_report is False


def test_endpoint_invalid_takes_priority_over_waf_headers():
    """404 with a stray WAF header should still be ENDPOINT_INVALID, not WAF_BLOCKED."""
    resp = _mock_response(404, {"cf-ray": "abc-DFW"}, "Not Found")
    result = classify_response(resp, PAYLOAD)

    assert result.verdict == "ENDPOINT_INVALID"
    assert result.should_report is False


# ── ENCODED_SAFE ──────────────────────────────────────────────────────────

def test_encoded_safe():
    encoded_body = "<html>you searched for &lt;script&gt;alert(1)&lt;/script&gt;</html>"
    resp = _mock_response(200, {}, encoded_body)
    result = classify_response(resp, PAYLOAD)

    assert result.verdict == "ENCODED_SAFE"
    assert result.severity is None
    assert result.should_report is False


def test_encoded_safe_quote_payload():
    payload = '"><script>alert(1)</script>'
    encoded_body = "value=&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"
    resp = _mock_response(200, {}, encoded_body)
    result = classify_response(resp, payload)

    assert result.verdict == "ENCODED_SAFE"
    assert result.should_report is False


# ── INCONCLUSIVE (safety-net fallback) ───────────────────────────────────

def test_inconclusive_no_reflection_at_all():
    resp = _mock_response(200, {}, "<html>nothing relevant here</html>")
    result = classify_response(resp, PAYLOAD)

    assert result.verdict == "INCONCLUSIVE"
    assert result.should_report is False
    assert result.severity is None


# ── detect_waf() unit coverage ────────────────────────────────────────────

@pytest.mark.parametrize("vendor,headers,body", WAF_BLOCK_CASES)
def test_detect_waf_header_signal(vendor, headers, body):
    assert detect_waf(headers, body) == vendor


def test_detect_waf_none_when_no_signature():
    assert detect_waf({}, "just a normal page") is None


def test_detect_waf_case_insensitive_headers():
    assert detect_waf({"CF-Ray": "abc-DFW"}, "") == "Cloudflare"


def test_detect_waf_body_marker_case_insensitive():
    assert detect_waf({}, "SORRY, YOU HAVE BEEN BLOCKED") == "Cloudflare"


# ── classify_error_signature() — SQLi error-based ────────────────────────

def test_sqli_error_confirmed():
    result = classify_error_signature(200, {}, "...", "you have an error in your sql syntax")

    assert result.verdict == "CONFIRMED"
    assert result.severity == "Critical"
    assert result.should_report is True
    assert result.waf_detected is None


def test_sqli_error_no_match_is_inconclusive():
    result = classify_error_signature(200, {}, "normal page", None)

    assert result.verdict == "INCONCLUSIVE"
    assert result.should_report is False


@pytest.mark.parametrize("status_code", [403, 406, 429])
def test_sqli_error_waf_blocked(status_code):
    result = classify_error_signature(status_code, {"cf-ray": "abc-DFW"}, "Sorry, you have been blocked", None)

    assert result.verdict == "WAF_BLOCKED"
    assert result.severity == "Medium"
    assert result.should_report is False
    assert result.waf_detected == "Cloudflare"


@pytest.mark.parametrize("status_code", [404, 400])
def test_sqli_error_endpoint_invalid(status_code):
    result = classify_error_signature(status_code, {}, "Not Found", None)

    assert result.verdict == "ENDPOINT_INVALID"
    assert result.should_report is False


def test_sqli_error_endpoint_invalid_beats_error_match():
    """A stray SQL-error-looking string on a 404 page must not be CONFIRMED."""
    result = classify_error_signature(404, {}, "you have an error in your sql syntax", "you have an error in your sql syntax")

    assert result.verdict == "ENDPOINT_INVALID"
    assert result.should_report is False


def test_sqli_error_not_confirmed_when_waf_present_even_with_match():
    result = classify_error_signature(200, {"cf-ray": "abc-DFW"}, "you have an error in your sql syntax", "you have an error in your sql syntax")

    assert result.verdict != "CONFIRMED"
    assert result.should_report is False
    assert result.waf_detected == "Cloudflare"


# ── classify_blind_signal() — SQLi boolean/time-based blind ─────────────

def test_blind_signal_confirmed():
    result = classify_blind_signal(
        200, {}, "true-condition-page",
        200, {}, "false-condition-page-shorter",
        True, "Boolean-based blind SQLi",
    )

    assert result.verdict == "CONFIRMED"
    assert result.severity == "Critical"
    assert result.should_report is True
    assert result.waf_detected is None


def test_blind_signal_no_differential_is_inconclusive():
    result = classify_blind_signal(
        200, {}, "same page",
        200, {}, "same page",
        False, "Boolean-based blind SQLi",
    )

    assert result.verdict == "INCONCLUSIVE"
    assert result.should_report is False


def test_blind_signal_waf_blocked_on_either_response():
    result = classify_blind_signal(
        200, {}, "normal response",
        403, {"cf-ray": "abc-DFW"}, "Sorry, you have been blocked",
        True, "MySQL time-based blind SQLi",
    )

    assert result.verdict == "WAF_BLOCKED"
    assert result.should_report is False
    assert result.waf_detected == "Cloudflare"


@pytest.mark.parametrize("status_code", [404, 400])
def test_blind_signal_endpoint_invalid_when_both_responses_fail(status_code):
    """Only when *both* requests hit the same invalid status is the endpoint
    itself considered broken, independent of the injected payload."""
    result = classify_blind_signal(
        status_code, {}, "Not Found",
        status_code, {}, "Not Found",
        True, "Boolean-based blind SQLi",
    )

    assert result.verdict == "ENDPOINT_INVALID"
    assert result.should_report is False


def test_blind_signal_confirmed_on_status_split_not_misread_as_invalid():
    """A true=200 / false=404 split caused by the injected condition is the
    boolean-based signal itself — must be CONFIRMED, not ENDPOINT_INVALID."""
    result = classify_blind_signal(
        200, {}, "true-condition-page",
        404, {}, "Not Found",
        True, "Boolean-based blind SQLi",
    )

    assert result.verdict == "CONFIRMED"
    assert result.should_report is True


def test_blind_signal_not_confirmed_when_waf_present_without_blocking_status():
    """WAF header present but status 200 (not actually blocked) with a real
    differential should still not be trusted as CONFIRMED — the WAF cookie
    alone means the target is behind a WAF that could be interfering."""
    result = classify_blind_signal(
        200, {"cf-ray": "abc-DFW"}, "true-condition-page",
        200, {"cf-ray": "abc-DFW"}, "false-condition-page-shorter",
        True, "Boolean-based blind SQLi",
    )

    assert result.verdict != "CONFIRMED"
    assert result.should_report is False


# ── classify_signature_match() — generic single-response signature match
# (shared by SQLi error-based via classify_error_signature, plus LFI/SSRF) ─

def test_signature_match_confirmed_with_custom_severity_and_label():
    result = classify_signature_match(200, {}, "...", "root:x:0:0", severity="High", signal_label="LFI indicator")

    assert result.verdict == "CONFIRMED"
    assert result.severity == "High"
    assert result.should_report is True
    assert result.waf_detected is None
    assert "LFI indicator" in result.reason
    assert "root:x:0:0" in result.reason


def test_signature_match_no_match_is_inconclusive():
    result = classify_signature_match(200, {}, "normal page", None, severity="Critical", signal_label="SSRF indicator")

    assert result.verdict == "INCONCLUSIVE"
    assert result.should_report is False


@pytest.mark.parametrize("status_code", [403, 406, 429])
def test_signature_match_waf_blocked(status_code):
    result = classify_signature_match(
        status_code, {"x-sucuri-id": "1"}, "Access Denied - Sucuri Website Firewall", None,
        severity="Critical", signal_label="SSRF indicator",
    )

    assert result.verdict == "WAF_BLOCKED"
    assert result.severity == "Medium"
    assert result.should_report is False
    assert result.waf_detected == "Sucuri"


@pytest.mark.parametrize("status_code", [404, 400])
def test_signature_match_endpoint_invalid(status_code):
    result = classify_signature_match(status_code, {}, "Not Found", None, severity="High", signal_label="LFI indicator")

    assert result.verdict == "ENDPOINT_INVALID"
    assert result.should_report is False


def test_signature_match_endpoint_invalid_beats_signal_match():
    result = classify_signature_match(404, {}, "root:x:0:0", "root:x:0:0", severity="High", signal_label="LFI indicator")

    assert result.verdict == "ENDPOINT_INVALID"
    assert result.should_report is False


def test_signature_match_not_confirmed_when_waf_present_even_with_match():
    result = classify_signature_match(
        200, {"cf-ray": "abc-DFW"}, "root:x:0:0", "root:x:0:0",
        severity="High", signal_label="LFI indicator",
    )

    assert result.verdict != "CONFIRMED"
    assert result.should_report is False
    assert result.waf_detected == "Cloudflare"


def test_classify_error_signature_still_delegates_correctly():
    """Backward-compat wrapper must still behave exactly as before the refactor."""
    result = classify_error_signature(200, {}, "...", "you have an error in your sql syntax")

    assert result.verdict == "CONFIRMED"
    assert result.severity == "Critical"
    assert result.should_report is True
    assert "SQL error signature" in result.reason


# ── classify_signature_match() — expected_status_codes (open redirect) ───

def test_signature_match_confirmed_on_redirect_status():
    result = classify_signature_match(
        302, {}, "", "https://evil.com/",
        severity="Medium", signal_label="Open Redirect Location header",
        expected_status_codes=frozenset({301, 302, 303, 307, 308}),
    )

    assert result.verdict == "CONFIRMED"
    assert result.severity == "Medium"
    assert result.should_report is True


def test_signature_match_default_status_200_still_required_when_unset():
    """Without overriding expected_status_codes, a 302 must not confirm —
    this is the exact backward-compat guarantee the SQLi/LFI/SSRF callers rely on."""
    result = classify_signature_match(302, {}, "", "some signal", severity="Critical", signal_label="signature")

    assert result.verdict != "CONFIRMED"
    assert result.should_report is False


def test_signature_match_redirect_status_but_no_matching_location_is_inconclusive():
    result = classify_signature_match(
        302, {}, "", None,
        severity="Medium", signal_label="Open Redirect Location header",
        expected_status_codes=frozenset({301, 302, 303, 307, 308}),
    )

    assert result.verdict == "INCONCLUSIVE"
    assert result.should_report is False


def test_signature_match_redirect_not_confirmed_when_waf_present():
    result = classify_signature_match(
        302, {"cf-ray": "abc-DFW"}, "", "https://evil.com/",
        severity="Medium", signal_label="Open Redirect Location header",
        expected_status_codes=frozenset({301, 302, 303, 307, 308}),
    )

    assert result.verdict != "CONFIRMED"
    assert result.should_report is False
    assert result.waf_detected == "Cloudflare"


# ── classify_graphql_introspection() — GraphQL introspection probe ──────

def _schema_body(type_names=("Query",)):
    return json.dumps({
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "types": [{"name": n} for n in type_names],
            }
        }
    })


def test_graphql_confirmed_when_schema_present():
    result = classify_graphql_introspection(200, {}, _schema_body())

    assert result.verdict == "CONFIRMED"
    assert result.severity == "Medium"
    assert result.should_report is True
    assert result.waf_detected is None


def test_graphql_not_confirmed_when_waf_present_even_with_schema():
    result = classify_graphql_introspection(200, {"cf-ray": "abc-DFW"}, _schema_body())

    assert result.verdict != "CONFIRMED"
    assert result.should_report is False
    assert result.waf_detected == "Cloudflare"


def test_graphql_bare_schema_key_without_types_is_not_confirmed():
    """A non-GraphQL JSON API that happens to echo back `{"data": {"__schema":
    null}}` (or an empty object) must not be mistaken for a live schema."""
    body = json.dumps({"data": {"__schema": None}})
    result = classify_graphql_introspection(200, {}, body)

    assert result.verdict != "CONFIRMED"


@pytest.mark.parametrize("message", [
    'Cannot query field "__schema" on type Query.',
    "GraphQL introspection is disabled",
    "Introspection is not allowed",
])
def test_graphql_introspection_disabled(message):
    body = json.dumps({"errors": [{"message": message}]})
    result = classify_graphql_introspection(200, {}, body)

    assert result.verdict == "INTROSPECTION_DISABLED"
    assert result.should_report is False
    assert result.severity is None


def test_graphql_generic_error_is_inconclusive_not_disabled():
    """An unrelated GraphQL error (bad syntax, unknown field typo, etc.) says
    nothing about whether introspection specifically is disabled."""
    body = json.dumps({"errors": [{"message": "Syntax Error: Unexpected Name \"foo\""}]})
    result = classify_graphql_introspection(200, {}, body)

    assert result.verdict == "INCONCLUSIVE"
    assert result.should_report is False


def test_graphql_non_json_body_is_inconclusive():
    result = classify_graphql_introspection(200, {}, "<html>not graphql at all</html>")

    assert result.verdict == "INCONCLUSIVE"
    assert result.should_report is False


@pytest.mark.parametrize("status_code", [404, 400])
def test_graphql_endpoint_invalid(status_code):
    result = classify_graphql_introspection(status_code, {}, "Not Found")

    assert result.verdict == "ENDPOINT_INVALID"
    assert result.should_report is False


@pytest.mark.parametrize("status_code", [403, 406, 429])
def test_graphql_waf_blocked(status_code):
    result = classify_graphql_introspection(
        status_code, {"cf-ray": "abc-DFW"}, "Sorry, you have been blocked",
    )

    assert result.verdict == "WAF_BLOCKED"
    assert result.severity == "Medium"
    assert result.should_report is False
    assert result.waf_detected == "Cloudflare"
