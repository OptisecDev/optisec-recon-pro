"""
Tests for the SQLi scanner (modules/vuln/sqli.py) wired through
modules/vuln/waf_aware_classifier.py's classify_error_signature() and
classify_blind_signal().

No real network calls: requests.Session.get/post are monkeypatched to a
canned responder, same "never hit real APIs in tests" convention as the
rest of the suite. Timing for the time-based blind path is controlled via
monkeypatching time.time() instead of actually sleeping.
"""

import os
import sys
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

from modules.vuln import sqli


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


def _patch_session(monkeypatch, get_responder=None, post_responder=None):
    def fake_get(self, url, **kwargs):
        return get_responder(url, kwargs) if get_responder else _FakeResponse()

    def fake_post(self, url, **kwargs):
        return post_responder(url, kwargs) if post_responder else _FakeResponse()

    monkeypatch.setattr(requests.Session, "get", fake_get)
    monkeypatch.setattr(requests.Session, "post", fake_post)


def _param(url):
    return parse_qs(urlparse(url).query).get("id", [""])[0]


# ── _error_based_scan ─────────────────────────────────────────────────────

def test_error_based_scan_confirms_real_sqli(monkeypatch):
    def responder(url, kwargs):
        if _param(url) == "'":
            return _FakeResponse(200, {}, "You have an error in your SQL syntax near ''")
        return _FakeResponse(200, {}, "normal page")

    _patch_session(monkeypatch, get_responder=responder)
    session = requests.Session()
    parsed = urlparse("https://example.com/item?id=1")
    params = parse_qs(parsed.query)

    findings = sqli._error_based_scan(session, parsed, params)

    assert len(findings) == 1
    assert findings[0]["verdict"] == "CONFIRMED"
    assert findings[0]["severity"] == "Critical"
    assert findings[0]["waf_detected"] is None
    assert findings[0]["type"] == "SQL Injection"


def test_error_based_scan_skips_waf_blocked(monkeypatch):
    def responder(url, kwargs):
        return _FakeResponse(403, {"cf-ray": "abc-DFW"}, "Sorry, you have been blocked")

    _patch_session(monkeypatch, get_responder=responder)
    session = requests.Session()
    parsed = urlparse("https://example.com/item?id=1")
    params = parse_qs(parsed.query)

    findings = sqli._error_based_scan(session, parsed, params)

    assert findings == []


def test_error_based_scan_stops_early_on_endpoint_invalid(monkeypatch):
    calls = []

    def responder(url, kwargs):
        calls.append(url)
        return _FakeResponse(404, {}, "Not Found")

    _patch_session(monkeypatch, get_responder=responder)
    session = requests.Session()
    parsed = urlparse("https://example.com/missing?id=1")
    params = parse_qs(parsed.query)

    findings = sqli._error_based_scan(session, parsed, params)

    assert findings == []
    assert len(calls) == 1  # broke after the first payload instead of trying all 10


def test_error_based_scan_no_signal_yields_no_findings(monkeypatch):
    _patch_session(monkeypatch, get_responder=lambda url, kwargs: _FakeResponse(200, {}, "ordinary page"))
    session = requests.Session()
    parsed = urlparse("https://example.com/item?id=1")
    params = parse_qs(parsed.query)

    findings = sqli._error_based_scan(session, parsed, params)

    assert findings == []


# ── _blind_scan — boolean-based ──────────────────────────────────────────

def test_blind_scan_boolean_based_confirmed(monkeypatch):
    def responder(url, kwargs):
        val = _param(url)
        if val == "1 AND 1=1":
            return _FakeResponse(200, {}, "A" * 500)
        if val == "1 AND 1=2":
            return _FakeResponse(500, {}, "error")
        return _FakeResponse(200, {}, "normal")

    _patch_session(monkeypatch, get_responder=responder)
    session = requests.Session()
    parsed = urlparse("https://example.com/item?id=1")
    params = parse_qs(parsed.query)

    findings = sqli._blind_scan(session, parsed, params)

    boolean_findings = [f for f in findings if f["type"] == "SQL Injection (Blind)"]
    assert len(boolean_findings) == 1
    assert boolean_findings[0]["verdict"] == "CONFIRMED"
    assert boolean_findings[0]["severity"] == "Critical"


def test_blind_scan_boolean_based_waf_blocked_not_reported(monkeypatch):
    def responder(url, kwargs):
        val = _param(url)
        if val == "1 AND 1=2":
            return _FakeResponse(403, {"x-sucuri-id": "1"}, "Access Denied - Sucuri Website Firewall")
        return _FakeResponse(200, {}, "A" * 500)

    _patch_session(monkeypatch, get_responder=responder)
    session = requests.Session()
    parsed = urlparse("https://example.com/item?id=1")
    params = parse_qs(parsed.query)

    findings = sqli._blind_scan(session, parsed, params)

    assert findings == []


def test_blind_scan_status_split_from_404_is_still_confirmed(monkeypatch):
    """A true=200 / false=404 split from the injected condition is the
    boolean-based signal itself, not an ENDPOINT_INVALID false negative."""
    def responder(url, kwargs):
        val = _param(url)
        if val == "1 AND 1=2":
            return _FakeResponse(404, {}, "Not Found" + "x" * 500)
        return _FakeResponse(200, {}, "normal page content here")

    _patch_session(monkeypatch, get_responder=responder)
    session = requests.Session()
    parsed = urlparse("https://example.com/item?id=1")
    params = parse_qs(parsed.query)

    findings = sqli._blind_scan(session, parsed, params)

    boolean_findings = [f for f in findings if f["type"] == "SQL Injection (Blind)"]
    assert len(boolean_findings) == 1
    assert boolean_findings[0]["verdict"] == "CONFIRMED"


def test_blind_scan_both_invalid_reports_nothing(monkeypatch):
    _patch_session(monkeypatch, get_responder=lambda url, kwargs: _FakeResponse(404, {}, "Not Found"))
    session = requests.Session()
    parsed = urlparse("https://example.com/missing?id=1")
    params = parse_qs(parsed.query)

    findings = sqli._blind_scan(session, parsed, params)

    assert findings == []


# ── _blind_scan — time-based (timing controlled via time.time patch) ────

def test_blind_scan_time_based_confirmed(monkeypatch):
    """Boolean check produces no signal (identical responses), so the scan
    falls through to the time-based check. time.time() is patched so the
    test doesn't actually sleep for the simulated delay."""
    def responder(url, kwargs):
        return _FakeResponse(200, {}, "same content")

    _patch_session(monkeypatch, get_responder=responder)

    # The boolean-based check doesn't call time.time() at all (identical
    # responses -> no signal, falls through). Only the time-based check
    # does: normal t0/t1, then sleep t0/t1.
    time_values = iter([100.0, 100.1, 200.0, 203.0])
    monkeypatch.setattr(sqli.time, "time", lambda: next(time_values))

    session = requests.Session()
    parsed = urlparse("https://example.com/item?id=1")
    params = parse_qs(parsed.query)

    findings = sqli._blind_scan(session, parsed, params)

    time_findings = [f for f in findings if f["type"] == "SQL Injection (Time-Based Blind)"]
    assert len(time_findings) == 1
    assert time_findings[0]["verdict"] == "CONFIRMED"
    assert time_findings[0]["severity"] == "Critical"


def test_blind_scan_time_based_waf_blocked_not_reported(monkeypatch):
    def responder(url, kwargs):
        val = _param(url)
        if val == "1 AND SLEEP(3)--":
            return _FakeResponse(429, {"cf-ray": "abc-DFW"}, "Sorry, you have been blocked")
        return _FakeResponse(200, {}, "same content")

    _patch_session(monkeypatch, get_responder=responder)
    time_values = iter([100.0, 100.1, 200.0, 203.0])
    monkeypatch.setattr(sqli.time, "time", lambda: next(time_values))

    session = requests.Session()
    parsed = urlparse("https://example.com/item?id=1")
    params = parse_qs(parsed.query)

    findings = sqli._blind_scan(session, parsed, params)

    assert findings == []


# ── _scan_forms ───────────────────────────────────────────────────────────

def test_scan_forms_confirms_real_sqli(monkeypatch):
    form_page = """
    <html><body>
    <form method="post" action="/search">
        <input type="text" name="q" value="test">
    </form>
    </body></html>
    """

    def get_responder(url, kwargs):
        return _FakeResponse(200, {}, form_page)

    def post_responder(url, kwargs):
        data = kwargs.get("data", {})
        if data.get("q") == "'":
            return _FakeResponse(200, {}, "SQL syntax error near unexpected token")
        return _FakeResponse(200, {}, "normal")

    _patch_session(monkeypatch, get_responder=get_responder, post_responder=post_responder)
    session = requests.Session()

    findings = sqli._scan_forms(session, "https://example.com/search")

    assert len(findings) == 1
    assert findings[0]["verdict"] == "CONFIRMED"
    assert findings[0]["parameter"] == "q"


def test_scan_forms_waf_blocked_not_reported(monkeypatch):
    form_page = """
    <html><body>
    <form method="post" action="/search">
        <input type="text" name="q" value="test">
    </form>
    </body></html>
    """

    def get_responder(url, kwargs):
        return _FakeResponse(200, {}, form_page)

    def post_responder(url, kwargs):
        return _FakeResponse(406, {"akamai-grn": "0.abc"}, "Access Denied - akamai reference #18.abc")

    _patch_session(monkeypatch, get_responder=get_responder, post_responder=post_responder)
    session = requests.Session()

    findings = sqli._scan_forms(session, "https://example.com/search")

    assert findings == []


# ── scan_sqli — end-to-end wiring ────────────────────────────────────────

def test_scan_sqli_end_to_end_only_reports_confirmed(monkeypatch):
    def get_responder(url, kwargs):
        if _param(url) == "'":
            return _FakeResponse(200, {}, "you have an error in your sql syntax")
        return _FakeResponse(200, {}, "<html><body>no forms here</body></html>")

    _patch_session(monkeypatch, get_responder=get_responder)

    findings = sqli.scan_sqli("https://example.com/item?id=1")

    assert len(findings) == 1
    assert findings[0]["verdict"] == "CONFIRMED"
    assert findings[0]["type"] == "SQL Injection"
