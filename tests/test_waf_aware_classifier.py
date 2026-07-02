"""
Tests for WAF-aware XSS classification (modules/vuln/waf_aware_classifier.py).

Covers the four verdicts — CONFIRMED, WAF_BLOCKED, ENDPOINT_INVALID,
ENCODED_SAFE — plus the INCONCLUSIVE safety-net fallback. No real network
calls: responses are built via httpx.MockTransport, mirroring the project's
existing "never hit real APIs in tests" convention (see
tests/test_darkweb_monitor.py).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
import pytest

from modules.vuln.waf_aware_classifier import (
    classify,
    classify_response,
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
