"""
Tests for the Open Redirect scanner (modules/vuln/open_redirect.py) wired
through modules/vuln/waf_aware_classifier.py's classify_signature_match()
(with expected_status_codes overridden to the 3xx redirect set).

No real network calls: requests.Session.get is monkeypatched to a canned
responder, same convention as tests/test_sqli.py / test_lfi.py / test_ssrf.py.

Non-CONFIRMED verdicts (WAF_BLOCKED/ENDPOINT_INVALID/INCONCLUSIVE) are now
retained in the scanner's return value instead of being discarded — only
web/app.py's include_in_report flag hides them from the client-facing
report. So these tests assert on the *verdict* of what comes back (never
CONFIRMED for a blocked/inconclusive probe) rather than `findings == []`.
"""

import os
import sys
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

from modules.vuln import open_redirect


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


def _patch_session(monkeypatch, responder):
    def fake_get(self, url, **kwargs):
        return responder(url, kwargs)

    monkeypatch.setattr(requests.Session, "get", fake_get)


def _param(url, name="redirect"):
    return parse_qs(urlparse(url).query).get(name, [""])[0]


def test_scan_open_redirect_confirms_real_redirect(monkeypatch):
    def responder(url, kwargs):
        val = _param(url)
        if "evil.com" in val:
            return _FakeResponse(302, {"Location": "https://evil.com/"}, "")
        return _FakeResponse(200, {}, "<html>normal page</html>")

    _patch_session(monkeypatch, responder)

    findings = open_redirect.scan_open_redirect("https://example.com/go?redirect=/home")

    assert len(findings) == 1
    assert findings[0]["type"] == "Open Redirect"
    assert findings[0]["verdict"] == "CONFIRMED"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["waf_detected"] is None


def test_scan_open_redirect_ignores_same_site_redirect(monkeypatch):
    """A 3xx with a Location header that does NOT point off-site must not be
    confirmed — this was a real false-positive source in the old check
    (`status in 3xx and loc` regardless of where `loc` pointed). It's still
    retained as an INCONCLUSIVE record now, just never CONFIRMED."""
    def responder(url, kwargs):
        return _FakeResponse(302, {"Location": "/login"}, "")

    _patch_session(monkeypatch, responder)

    findings = open_redirect.scan_open_redirect("https://example.com/go?redirect=/home")

    assert len(findings) == 1
    assert findings[0]["verdict"] == "INCONCLUSIVE"


def test_scan_open_redirect_retains_waf_blocked_without_confirming(monkeypatch):
    calls = []

    def responder(url, kwargs):
        calls.append(url)
        return _FakeResponse(403, {"cf-ray": "abc-DFW"}, "Sorry, you have been blocked")

    _patch_session(monkeypatch, responder)

    findings = open_redirect.scan_open_redirect("https://example.com/go?redirect=/home")

    # WAF_BLOCKED doesn't stop the scan early (unlike ENDPOINT_INVALID) — all
    # payloads are still tried — but only the last one is kept as the
    # retained record, not one row per payload.
    assert len(calls) == len(open_redirect.REDIRECT_PAYLOADS)
    assert len(findings) == 1
    assert findings[0]["verdict"] == "WAF_BLOCKED"
    assert findings[0]["waf_detected"] == "Cloudflare"


def test_scan_open_redirect_stops_early_on_endpoint_invalid(monkeypatch):
    calls = []

    def responder(url, kwargs):
        calls.append(url)
        return _FakeResponse(404, {}, "Not Found")

    _patch_session(monkeypatch, responder)

    findings = open_redirect.scan_open_redirect("https://example.com/missing?redirect=/home")

    assert len(calls) == 1
    assert len(findings) == 1
    assert findings[0]["verdict"] == "ENDPOINT_INVALID"


def test_scan_open_redirect_no_redirect_retained_as_inconclusive(monkeypatch):
    _patch_session(monkeypatch, lambda url, kwargs: _FakeResponse(200, {}, "ordinary page"))

    findings = open_redirect.scan_open_redirect("https://example.com/go?redirect=/home")

    assert len(findings) == 1
    assert findings[0]["verdict"] == "INCONCLUSIVE"


def test_scan_open_redirect_not_confirmed_when_waf_present_even_with_evil_location(monkeypatch):
    def responder(url, kwargs):
        val = _param(url)
        if "evil.com" in val:
            return _FakeResponse(302, {"Location": "https://evil.com/", "cf-ray": "abc-DFW"}, "")
        return _FakeResponse(200, {"cf-ray": "abc-DFW"}, "<html>normal page</html>")

    _patch_session(monkeypatch, responder)

    findings = open_redirect.scan_open_redirect("https://example.com/go?redirect=/home")

    assert all(f["verdict"] != "CONFIRMED" for f in findings)
