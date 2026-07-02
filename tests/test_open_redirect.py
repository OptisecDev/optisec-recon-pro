"""
Tests for the Open Redirect scanner (modules/vuln/open_redirect.py) wired
through modules/vuln/waf_aware_classifier.py's classify_signature_match()
(with expected_status_codes overridden to the 3xx redirect set).

No real network calls: requests.Session.get is monkeypatched to a canned
responder, same convention as tests/test_sqli.py / test_lfi.py / test_ssrf.py.
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
    reported — this was a real false-positive source in the old check
    (`status in 3xx and loc` regardless of where `loc` pointed)."""
    def responder(url, kwargs):
        return _FakeResponse(302, {"Location": "/login"}, "")

    _patch_session(monkeypatch, responder)

    findings = open_redirect.scan_open_redirect("https://example.com/go?redirect=/home")

    assert findings == []


def test_scan_open_redirect_skips_waf_blocked(monkeypatch):
    def responder(url, kwargs):
        return _FakeResponse(403, {"cf-ray": "abc-DFW"}, "Sorry, you have been blocked")

    _patch_session(monkeypatch, responder)

    findings = open_redirect.scan_open_redirect("https://example.com/go?redirect=/home")

    assert findings == []


def test_scan_open_redirect_stops_early_on_endpoint_invalid(monkeypatch):
    calls = []

    def responder(url, kwargs):
        calls.append(url)
        return _FakeResponse(404, {}, "Not Found")

    _patch_session(monkeypatch, responder)

    findings = open_redirect.scan_open_redirect("https://example.com/missing?redirect=/home")

    assert findings == []
    assert len(calls) == 1


def test_scan_open_redirect_no_redirect_yields_no_findings(monkeypatch):
    _patch_session(monkeypatch, lambda url, kwargs: _FakeResponse(200, {}, "ordinary page"))

    findings = open_redirect.scan_open_redirect("https://example.com/go?redirect=/home")

    assert findings == []


def test_scan_open_redirect_not_confirmed_when_waf_present_even_with_evil_location(monkeypatch):
    def responder(url, kwargs):
        val = _param(url)
        if "evil.com" in val:
            return _FakeResponse(302, {"Location": "https://evil.com/", "cf-ray": "abc-DFW"}, "")
        return _FakeResponse(200, {"cf-ray": "abc-DFW"}, "<html>normal page</html>")

    _patch_session(monkeypatch, responder)

    findings = open_redirect.scan_open_redirect("https://example.com/go?redirect=/home")

    assert findings == []
