"""
Tests for the GraphQL introspection scanner (modules/vuln/graphql_probe.py)
wired through modules/vuln/waf_aware_classifier.py's
classify_graphql_introspection().

No real network calls: requests.Session.post/get are monkeypatched to
canned responders, same convention as tests/test_ssrf.py.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

from modules.vuln import graphql_probe

SCHEMA_BODY = json.dumps({
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "types": [{"name": "Query"}],
        }
    }
})

INTROSPECTION_DISABLED_BODY = json.dumps({
    "errors": [{"message": 'Cannot query field "__schema" on type Query.'}]
})


class _FakeResponse:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


def _patch_session(monkeypatch, post_responder=None, get_responder=None):
    calls = []

    def fake_post(self, url, **kwargs):
        calls.append(("POST", url))
        if post_responder is None:
            return _FakeResponse(404, {}, "")
        return post_responder(url, kwargs)

    def fake_get(self, url, **kwargs):
        calls.append(("GET", url))
        if get_responder is None:
            return _FakeResponse(404, {}, "")
        return get_responder(url, kwargs)

    monkeypatch.setattr(requests.Session, "post", fake_post)
    monkeypatch.setattr(requests.Session, "get", fake_get)
    return calls


def test_scan_graphql_confirms_introspection_enabled_via_post(monkeypatch):
    def post_responder(url, kwargs):
        if url == "https://example.com/graphql":
            return _FakeResponse(200, {}, SCHEMA_BODY)
        return _FakeResponse(404, {}, "")

    calls = _patch_session(monkeypatch, post_responder=post_responder)

    findings = graphql_probe.scan_graphql("https://example.com/")

    # First candidate path (/graphql) confirms on POST alone — the scan
    # stops there, so no GET fallback and no further candidate paths.
    assert len(findings) == 1
    assert findings[0]["type"] == "GraphQL Introspection"
    assert findings[0]["verdict"] == "CONFIRMED"
    assert findings[0]["method"] == "POST"
    assert findings[0]["path"] == "/graphql"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["waf_detected"] is None
    assert all(method == "POST" for method, _ in calls)
    # existence probe + full introspection probe, both against /graphql
    assert calls == [
        ("POST", "https://example.com/graphql"),
        ("POST", "https://example.com/graphql"),
    ]


def test_scan_graphql_get_fallback_used_when_post_is_not_graphql(monkeypatch):
    def post_responder(url, kwargs):
        return _FakeResponse(404, {}, "")

    def get_responder(url, kwargs):
        if url == "https://example.com/graphql":
            return _FakeResponse(200, {}, SCHEMA_BODY)
        return _FakeResponse(404, {}, "")

    calls = _patch_session(monkeypatch, post_responder=post_responder, get_responder=get_responder)

    findings = graphql_probe.scan_graphql("https://example.com/")

    assert len(findings) == 1
    assert findings[0]["verdict"] == "CONFIRMED"
    assert findings[0]["method"] == "GET"
    assert findings[0]["path"] == "/graphql"
    # POST existence probe (404, not decisive) + GET existence probe
    # (confirms) + GET full-introspection follow-up, all for /graphql only.
    assert calls == [
        ("POST", "https://example.com/graphql"),
        ("GET", "https://example.com/graphql"),
        ("GET", "https://example.com/graphql"),
    ]


def test_scan_graphql_introspection_disabled_skips_get_fallback(monkeypatch):
    def post_responder(url, kwargs):
        return _FakeResponse(200, {}, INTROSPECTION_DISABLED_BODY)

    calls = _patch_session(monkeypatch, post_responder=post_responder)

    findings = graphql_probe.scan_graphql("https://example.com/")

    # INTROSPECTION_DISABLED is decisive on POST alone, for every candidate
    # path — no GET fallback anywhere, and every path gets a retained entry.
    assert len(findings) == len(graphql_probe.GRAPHQL_CANDIDATE_PATHS)
    assert all(f["verdict"] == "INTROSPECTION_DISABLED" for f in findings)
    assert all(method == "POST" for method, _ in calls)
    assert len(calls) == len(graphql_probe.GRAPHQL_CANDIDATE_PATHS)


def test_scan_graphql_waf_blocked_retained_without_confirming(monkeypatch):
    def post_responder(url, kwargs):
        return _FakeResponse(429, {"x-amzn-waf-action": "block"}, "Request blocked AWS WAF")

    _patch_session(monkeypatch, post_responder=post_responder)

    findings = graphql_probe.scan_graphql("https://example.com/")

    assert len(findings) == len(graphql_probe.GRAPHQL_CANDIDATE_PATHS)
    assert all(f["verdict"] == "WAF_BLOCKED" for f in findings)
    assert all(f["waf_detected"] == "AWS WAF" for f in findings)


def test_scan_graphql_no_endpoint_anywhere_tries_every_path_both_methods(monkeypatch):
    calls = _patch_session(monkeypatch)  # both POST and GET always 404

    findings = graphql_probe.scan_graphql("https://example.com/")

    assert len(findings) == len(graphql_probe.GRAPHQL_CANDIDATE_PATHS)
    assert all(f["verdict"] == "ENDPOINT_INVALID" for f in findings)
    # ENDPOINT_INVALID isn't decisive, so GET fallback is tried for every path.
    assert len(calls) == 2 * len(graphql_probe.GRAPHQL_CANDIDATE_PATHS)


def test_scan_graphql_stops_after_first_confirmed_path_even_if_later_paths_would_confirm(monkeypatch):
    def post_responder(url, kwargs):
        # Every candidate path would confirm — only the first one tried
        # should end up in the findings, per the one-primary-finding rule.
        return _FakeResponse(200, {}, SCHEMA_BODY)

    _patch_session(monkeypatch, post_responder=post_responder)

    findings = graphql_probe.scan_graphql("https://example.com/")

    assert len(findings) == 1
    assert findings[0]["path"] == graphql_probe.GRAPHQL_CANDIDATE_PATHS[0]


def test_scan_graphql_request_exception_treated_as_no_endpoint(monkeypatch):
    def post_responder(url, kwargs):
        raise requests.exceptions.ConnectionError("refused")

    def get_responder(url, kwargs):
        raise requests.exceptions.ConnectionError("refused")

    _patch_session(monkeypatch, post_responder=post_responder, get_responder=get_responder)

    findings = graphql_probe.scan_graphql("https://example.com/")

    assert findings == []
