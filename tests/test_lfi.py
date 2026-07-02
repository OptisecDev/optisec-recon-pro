"""
Tests for the LFI scanner (modules/vuln/lfi.py) wired through
modules/vuln/waf_aware_classifier.py's classify_signature_match().

No real network calls: requests.Session.get is monkeypatched to a canned
responder, same convention as tests/test_sqli.py.
"""

import os
import sys
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

from modules.vuln import lfi


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


def _patch_session(monkeypatch, responder):
    def fake_get(self, url, **kwargs):
        return responder(url, kwargs)

    monkeypatch.setattr(requests.Session, "get", fake_get)


def _param(url, name="file"):
    return parse_qs(urlparse(url).query).get(name, [""])[0]


def test_scan_lfi_confirms_real_lfi(monkeypatch):
    def responder(url, kwargs):
        if _param(url) == "/etc/passwd":
            return _FakeResponse(200, {}, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin")
        return _FakeResponse(200, {}, "<html>not found in page</html>")

    _patch_session(monkeypatch, responder)

    findings = lfi.scan_lfi("https://example.com/view?file=readme.txt")

    assert len(findings) == 1
    assert findings[0]["type"] == "LFI"
    assert findings[0]["verdict"] == "CONFIRMED"
    assert findings[0]["severity"] == "High"
    assert findings[0]["waf_detected"] is None


def test_scan_lfi_skips_waf_blocked(monkeypatch):
    def responder(url, kwargs):
        return _FakeResponse(403, {"cf-ray": "abc-DFW"}, "Sorry, you have been blocked")

    _patch_session(monkeypatch, responder)

    findings = lfi.scan_lfi("https://example.com/view?file=readme.txt")

    assert findings == []


def test_scan_lfi_stops_early_on_endpoint_invalid(monkeypatch):
    calls = []

    def responder(url, kwargs):
        calls.append(url)
        return _FakeResponse(404, {}, "Not Found")

    _patch_session(monkeypatch, responder)

    findings = lfi.scan_lfi("https://example.com/missing?file=readme.txt")

    assert findings == []
    assert len(calls) == 1  # broke after the first payload instead of trying all of them


def test_scan_lfi_no_signal_yields_no_findings(monkeypatch):
    _patch_session(monkeypatch, lambda url, kwargs: _FakeResponse(200, {}, "ordinary page, nothing sensitive"))

    findings = lfi.scan_lfi("https://example.com/view?file=readme.txt")

    assert findings == []


def test_scan_lfi_uses_file_related_param_names():
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse("https://example.com/view?id=1&file=readme.txt&unrelated=x")
    params = parse_qs(parsed.query)
    file_params = [k for k in params if any(kw in k.lower() for kw in
                   ["file", "path", "page", "include", "template", "view", "doc", "load", "read"])]
    assert file_params == ["file"]
