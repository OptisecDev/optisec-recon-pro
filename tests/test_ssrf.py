"""
Tests for the SSRF scanner (modules/vuln/ssrf.py) wired through
modules/vuln/waf_aware_classifier.py's classify_signature_match().

No real network calls: requests.Session.get is monkeypatched to a canned
responder, same convention as tests/test_sqli.py.

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

from modules.vuln import ssrf


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


def _patch_session(monkeypatch, responder):
    def fake_get(self, url, **kwargs):
        return responder(url, kwargs)

    monkeypatch.setattr(requests.Session, "get", fake_get)


def _param(url, name="url"):
    return parse_qs(urlparse(url).query).get(name, [""])[0]


def test_scan_ssrf_confirms_real_ssrf(monkeypatch):
    def responder(url, kwargs):
        if _param(url) == "http://169.254.169.254/latest/meta-data/":
            return _FakeResponse(200, {}, "ami-id\ninstance-id\ninstance-type")
        return _FakeResponse(200, {}, "<html>normal page</html>")

    _patch_session(monkeypatch, responder)

    findings = ssrf.scan_ssrf("https://example.com/fetch?url=https://example.com/image.png")

    assert len(findings) == 1
    assert findings[0]["type"] == "SSRF"
    assert findings[0]["verdict"] == "CONFIRMED"
    assert findings[0]["severity"] == "Critical"
    assert findings[0]["waf_detected"] is None


def test_scan_ssrf_indicator_match_is_case_insensitive(monkeypatch):
    def responder(url, kwargs):
        if _param(url) == "http://127.0.0.1/":
            return _FakeResponse(200, {}, "CONNECTION REFUSED")
        return _FakeResponse(200, {}, "<html>normal page</html>")

    _patch_session(monkeypatch, responder)

    findings = ssrf.scan_ssrf("https://example.com/fetch?url=https://example.com/image.png")

    assert len(findings) == 1
    assert findings[0]["verdict"] == "CONFIRMED"


def test_scan_ssrf_retains_waf_blocked_without_confirming(monkeypatch):
    calls = []

    def responder(url, kwargs):
        calls.append(url)
        return _FakeResponse(429, {"x-amzn-waf-action": "block"}, "Request blocked AWS WAF")

    _patch_session(monkeypatch, responder)

    findings = ssrf.scan_ssrf("https://example.com/fetch?url=https://example.com/image.png")

    # WAF_BLOCKED doesn't stop the scan early (unlike ENDPOINT_INVALID) — all
    # payloads are still tried — but only the last one is kept as the
    # retained record, not one row per payload.
    assert len(calls) == len(ssrf.SSRF_PAYLOADS)
    assert len(findings) == 1
    assert findings[0]["verdict"] == "WAF_BLOCKED"
    assert findings[0]["waf_detected"] == "AWS WAF"


def test_scan_ssrf_stops_early_on_endpoint_invalid(monkeypatch):
    calls = []

    def responder(url, kwargs):
        calls.append(url)
        return _FakeResponse(400, {}, "Bad Request")

    _patch_session(monkeypatch, responder)

    findings = ssrf.scan_ssrf("https://example.com/missing?url=https://example.com/image.png")

    assert len(calls) == 1
    assert len(findings) == 1
    assert findings[0]["verdict"] == "ENDPOINT_INVALID"


def test_scan_ssrf_no_signal_retained_as_inconclusive(monkeypatch):
    _patch_session(monkeypatch, lambda url, kwargs: _FakeResponse(200, {}, "ordinary page"))

    findings = ssrf.scan_ssrf("https://example.com/fetch?url=https://example.com/image.png")

    assert len(findings) == 1
    assert findings[0]["verdict"] == "INCONCLUSIVE"


def test_scan_ssrf_not_confirmed_when_waf_present_even_with_matching_indicator(monkeypatch):
    def responder(url, kwargs):
        if _param(url) == "http://169.254.169.254/latest/meta-data/":
            return _FakeResponse(200, {"cf-ray": "abc-DFW"}, "ami-id\ninstance-id")
        return _FakeResponse(200, {"cf-ray": "abc-DFW"}, "<html>normal page</html>")

    _patch_session(monkeypatch, responder)

    findings = ssrf.scan_ssrf("https://example.com/fetch?url=https://example.com/image.png")

    assert all(f["verdict"] != "CONFIRMED" for f in findings)
