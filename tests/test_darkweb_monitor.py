"""
Tests for Dark Web Monitoring (persistent watchlist + new-leak alerting).

All external HTTP calls are mocked via pytest's monkeypatch fixture — these
tests never hit real APIs. Mirrors tests/test_darkweb_intelligence.py's
conventions: plain pytest, async functions driven via asyncio.run(), a fake
aiohttp.ClientSession driven by a responder callback. Only project-approved
test targets are used: test@example.com, example.com.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aiohttp
import pytest

import modules.darkweb.monitor as mon


TEST_EMAIL = "test@example.com"
TEST_DOMAIN = "example.com"


def _run(coro):
    return asyncio.run(coro)


# ── Fake aiohttp plumbing — no real network calls ────────────────────────────

class _FakeResponse:
    def __init__(self, status=200, json_data=None):
        self.status = status
        self._json_data = {} if json_data is None else json_data

    async def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status >= 400:
            raise aiohttp.ClientResponseError(request_info=None, history=(), status=self.status)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeSession:
    def __init__(self, responder):
        self._responder = responder

    def get(self, url, **kwargs):
        return self._responder("GET", url, kwargs)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


def _patch_session(monkeypatch, responder):
    monkeypatch.setattr(mon.aiohttp, "ClientSession", lambda *a, **kw: _FakeSession(responder))


def _const_responder(resp: _FakeResponse):
    return lambda method, url, kwargs: resp


# ── 1. LeakCheck ──────────────────────────────────────────────────────────────

class TestLeakCheck:
    def test_public_endpoint_used_without_key(self, monkeypatch):
        monkeypatch.setattr(mon, "LEAKCHECK_API_KEY", "")
        seen_urls = []

        def responder(method, url, kwargs):
            seen_urls.append(url)
            return _FakeResponse(200, {"found": False})

        _patch_session(monkeypatch, responder)
        result = _run(mon._query_leakcheck(TEST_EMAIL))
        assert result["available"] is True
        assert result["found"] is False
        assert seen_urls[0] == mon.LEAKCHECK_PUBLIC_URL

    def test_pro_endpoint_used_with_key(self, monkeypatch):
        monkeypatch.setattr(mon, "LEAKCHECK_API_KEY", "fake-key")
        seen_urls = []

        def responder(method, url, kwargs):
            seen_urls.append(url)
            return _FakeResponse(200, {"found": True, "sources": [{"name": "BreachX"}], "fields": ["password"]})

        _patch_session(monkeypatch, responder)
        result = _run(mon._query_leakcheck(TEST_EMAIL))
        assert result["found"] is True
        assert result["sources"] == ["BreachX"]
        assert result["fields"] == ["password"]
        assert seen_urls[0] == mon.LEAKCHECK_PRO_URL.format(target=TEST_EMAIL)

    def test_string_sources_supported(self, monkeypatch):
        monkeypatch.setattr(mon, "LEAKCHECK_API_KEY", "")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(200, {"found": True, "sources": ["PlainSourceName"]})))
        result = _run(mon._query_leakcheck(TEST_EMAIL))
        assert result["sources"] == ["PlainSourceName"]

    def test_invalid_key_401(self, monkeypatch):
        monkeypatch.setattr(mon, "LEAKCHECK_API_KEY", "bad-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(401)))
        result = _run(mon._query_leakcheck(TEST_EMAIL))
        assert result["available"] is True
        assert "invalid" in result["error"].lower()
        assert result["found"] is False

    def test_explicit_failure_response(self, monkeypatch):
        monkeypatch.setattr(mon, "LEAKCHECK_API_KEY", "")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(200, {"success": False, "error": "rate limited"})))
        result = _run(mon._query_leakcheck(TEST_EMAIL))
        assert result["available"] is True
        assert result["found"] is False
        assert result["error"] == "rate limited"

    def test_network_error_never_raises(self, monkeypatch):
        monkeypatch.setattr(mon, "LEAKCHECK_API_KEY", "")

        def responder(method, url, kwargs):
            raise aiohttp.ClientConnectionError("boom")

        monkeypatch.setattr(mon.aiohttp, "ClientSession",
                             lambda *a, **kw: _FakeSession(responder))
        result = _run(mon._query_leakcheck(TEST_EMAIL))
        assert result["available"] is True
        assert result["found"] is False
        assert "boom" in result["error"]

    def test_not_found_result(self, monkeypatch):
        monkeypatch.setattr(mon, "LEAKCHECK_API_KEY", "")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(200, {"found": False})))
        result = _run(mon._query_leakcheck(TEST_DOMAIN))
        assert result["found"] is False
        assert result["sources"] == []


# ── 2. Fingerprinting ───────────────────────────────────────────────────────

class TestFingerprint:
    def test_deterministic(self):
        a = mon._fingerprint("breach", "Adobe", "alice")
        b = mon._fingerprint("breach", "Adobe", "alice")
        assert a == b

    def test_different_parts_differ(self):
        a = mon._fingerprint("breach", "Adobe", "alice")
        b = mon._fingerprint("breach", "Adobe", "bob")
        assert a != b

    def test_different_source_differs(self):
        a = mon._fingerprint("breach", "x")
        b = mon._fingerprint("paste", "x")
        assert a != b

    def test_handles_none_parts(self):
        # Should not raise even if a caller passes an empty/None-ish part.
        fp = mon._fingerprint("breach", "Adobe", "")
        assert isinstance(fp, str) and len(fp) == 32


# ── 3. build_leak_events ─────────────────────────────────────────────────────

class TestBuildLeakEvents:
    def test_empty_input_produces_no_events(self):
        events = mon.build_leak_events({}, None)
        assert events == []

    def test_breach_event(self):
        darkweb = {"breaches": [{"name": "Adobe", "title": "Adobe", "alias": "alice", "verified": True}]}
        events = mon.build_leak_events(darkweb, None)
        assert len(events) == 1
        assert events[0]["source"] == "breach"
        assert events[0]["severity"] == "critical"
        assert events[0]["title"] == "Adobe"

    def test_unverified_breach_is_high_severity(self):
        darkweb = {"breaches": [{"name": "Adobe", "verified": False}]}
        events = mon.build_leak_events(darkweb, None)
        assert events[0]["severity"] == "high"

    def test_paste_event(self):
        darkweb = {"pastes": [{"id": "p1", "source": "Pastebin"}]}
        events = mon.build_leak_events(darkweb, None)
        assert events[0]["source"] == "paste"
        assert events[0]["severity"] == "medium"
        assert "Pastebin" in events[0]["title"]

    def test_github_secret_event(self):
        darkweb = {"github_exposures": [{"html_url": "https://github.com/org/repo", "repository": "org/repo"}]}
        events = mon.build_leak_events(darkweb, None)
        assert events[0]["source"] == "github_secret"
        assert events[0]["severity"] == "high"

    def test_threat_actor_event(self):
        darkweb = {"threat_actors": ["APT99"]}
        events = mon.build_leak_events(darkweb, None)
        assert events[0]["source"] == "threat_actor"
        assert events[0]["severity"] == "critical"
        assert "APT99" in events[0]["title"]

    def test_leakcheck_not_found_produces_no_event(self):
        events = mon.build_leak_events({}, {"found": False, "sources": []})
        assert events == []

    def test_leakcheck_found_produces_events_per_source(self):
        leakcheck = {"found": True, "sources": ["BreachX", "BreachY"], "fields": ["password"]}
        events = mon.build_leak_events({}, leakcheck)
        assert len(events) == 2
        assert all(e["source"] == "leakcheck" for e in events)
        assert {e["title"] for e in events} == {"LeakCheck match: BreachX", "LeakCheck match: BreachY"}

    def test_combined_sources_all_present(self):
        darkweb = {
            "breaches": [{"name": "Adobe", "verified": True}],
            "pastes": [{"id": "p1"}],
            "github_exposures": [{"html_url": "u"}],
            "threat_actors": ["APT99"],
        }
        leakcheck = {"found": True, "sources": ["BreachZ"]}
        events = mon.build_leak_events(darkweb, leakcheck)
        sources = {e["source"] for e in events}
        assert sources == {"breach", "paste", "github_secret", "threat_actor", "leakcheck"}

    def test_every_event_has_a_fingerprint(self):
        darkweb = {"breaches": [{"name": "Adobe", "verified": True}], "pastes": [{"id": "p1"}]}
        events = mon.build_leak_events(darkweb, None)
        assert all(e.get("fingerprint") for e in events)


# ── 4. diff_new_events ───────────────────────────────────────────────────────

class TestDiffNewEvents:
    def test_all_new_when_nothing_known(self):
        events = [{"fingerprint": "a"}, {"fingerprint": "b"}]
        assert mon.diff_new_events(events, set()) == events

    def test_filters_known_fingerprints(self):
        events = [{"fingerprint": "a"}, {"fingerprint": "b"}]
        result = mon.diff_new_events(events, {"a"})
        assert result == [{"fingerprint": "b"}]

    def test_all_known_returns_empty(self):
        events = [{"fingerprint": "a"}, {"fingerprint": "b"}]
        assert mon.diff_new_events(events, {"a", "b"}) == []

    def test_empty_events_returns_empty(self):
        assert mon.diff_new_events([], {"a"}) == []


# ── 5. Arabic localization ───────────────────────────────────────────────────

class TestArabicLocalization:
    def test_localize_event_adds_arabic_labels(self):
        event = {"source": "breach", "severity": "critical", "title": "Adobe"}
        localized = mon.localize_event(event)
        assert localized["source_ar"] == mon.SOURCE_LABELS_AR["breach"]
        assert localized["severity_ar"] == mon.SEVERITY_LABELS_AR["critical"]
        # Original event dict is not mutated.
        assert "source_ar" not in event

    def test_localize_unknown_source_falls_back_to_raw_value(self):
        event = {"source": "mystery", "severity": "mystery"}
        localized = mon.localize_event(event)
        assert localized["source_ar"] == "mystery"
        assert localized["severity_ar"] == "mystery"

    def test_all_source_labels_are_arabic_strings(self):
        for label in mon.SOURCE_LABELS_AR.values():
            assert any("؀" <= ch <= "ۿ" for ch in label)

    def test_all_severity_labels_are_arabic_strings(self):
        for label in mon.SEVERITY_LABELS_AR.values():
            assert any("؀" <= ch <= "ۿ" for ch in label)

    def test_exposure_level_labels_cover_all_bands(self):
        assert set(mon.EXPOSURE_LEVEL_AR) == {"Clean", "Exposed", "Compromised", "Critical"}

    def test_no_new_events_message(self):
        msg = mon.build_arabic_alert_message(TEST_DOMAIN, [])
        assert TEST_DOMAIN in msg
        assert any("؀" <= ch <= "ۿ" for ch in msg)

    def test_new_events_message_lists_each_event(self):
        events = [
            {"source": "breach", "severity": "critical", "title": "Adobe"},
            {"source": "paste", "severity": "medium", "title": "Paste mention"},
        ]
        msg = mon.build_arabic_alert_message(TEST_DOMAIN, events)
        assert TEST_DOMAIN in msg
        assert "Adobe" in msg
        assert "Paste mention" in msg
        assert "2" in msg


# ── 6. run_monitor_check (orchestrator) ──────────────────────────────────────

async def _fake_gather_darkweb(target, include_pastes=True, include_github=True):
    return {
        "target": target, "target_type": "domain",
        "breaches": [{"name": "Adobe", "verified": True}],
        "pastes": [], "github_exposures": [], "threat_actors": [],
        "intelx": {}, "breachdirectory": {}, "leaklookup": {}, "threat_actor_detail": {},
        "exposure": {"score": 20, "exposure_level": "Exposed", "breakdown": [], "recommendations": []},
    }


async def _fake_leakcheck_found(target):
    return {"source": "leakcheck", "available": True, "target": target,
            "found": True, "sources": ["BreachZ"], "fields": [], "error": None}


async def _fake_leakcheck_not_found(target):
    return {"source": "leakcheck", "available": True, "target": target,
            "found": False, "sources": [], "fields": [], "error": None}


class TestRunMonitorCheck:
    def test_combines_darkweb_and_leakcheck_events(self, monkeypatch):
        import modules.osint.darkweb_intelligence as dw
        monkeypatch.setattr(dw, "gather_darkweb_intelligence", _fake_gather_darkweb)
        monkeypatch.setattr(mon, "_query_leakcheck", _fake_leakcheck_found)

        result = _run(mon.run_monitor_check(TEST_DOMAIN))
        assert result["target"] == TEST_DOMAIN
        sources = {e["source"] for e in result["events"]}
        assert sources == {"breach", "leakcheck"}
        assert result["exposure"]["score"] == 20
        assert result["leakcheck"]["found"] is True
        assert "checked_at" in result

    def test_no_leaks_produces_no_events(self, monkeypatch):
        import modules.osint.darkweb_intelligence as dw

        async def _clean(target, include_pastes=True, include_github=True):
            return {"target": target, "target_type": "domain", "breaches": [], "pastes": [],
                    "github_exposures": [], "threat_actors": [],
                    "exposure": {"score": 0, "exposure_level": "Clean", "breakdown": [], "recommendations": []}}

        monkeypatch.setattr(dw, "gather_darkweb_intelligence", _clean)
        monkeypatch.setattr(mon, "_query_leakcheck", _fake_leakcheck_not_found)

        result = _run(mon.run_monitor_check(TEST_DOMAIN))
        assert result["events"] == []
        assert result["exposure"]["exposure_level"] == "Clean"

    def test_darkweb_failure_degrades_gracefully(self, monkeypatch):
        import modules.osint.darkweb_intelligence as dw

        async def _boom(target, include_pastes=True, include_github=True):
            raise RuntimeError("upstream exploded")

        monkeypatch.setattr(dw, "gather_darkweb_intelligence", _boom)
        monkeypatch.setattr(mon, "_query_leakcheck", _fake_leakcheck_not_found)

        result = _run(mon.run_monitor_check(TEST_DOMAIN))
        assert result["events"] == []
        assert result["exposure"]["exposure_level"] == "Clean"

    def test_leakcheck_failure_degrades_gracefully(self, monkeypatch):
        import modules.osint.darkweb_intelligence as dw

        async def _boom(target):
            raise RuntimeError("leakcheck exploded")

        monkeypatch.setattr(dw, "gather_darkweb_intelligence", _fake_gather_darkweb)
        monkeypatch.setattr(mon, "_query_leakcheck", _boom)

        result = _run(mon.run_monitor_check(TEST_DOMAIN))
        assert result["leakcheck"]["available"] is False
        assert result["leakcheck"]["found"] is False
        # The darkweb-sourced breach event should still be present.
        assert any(e["source"] == "breach" for e in result["events"])

    def test_target_type_defaults_from_darkweb_result(self, monkeypatch):
        import modules.osint.darkweb_intelligence as dw
        monkeypatch.setattr(dw, "gather_darkweb_intelligence", _fake_gather_darkweb)
        monkeypatch.setattr(mon, "_query_leakcheck", _fake_leakcheck_not_found)

        result = _run(mon.run_monitor_check(TEST_DOMAIN))
        assert result["target_type"] == "domain"

    def test_explicit_target_type_is_preserved(self, monkeypatch):
        import modules.osint.darkweb_intelligence as dw
        monkeypatch.setattr(dw, "gather_darkweb_intelligence", _fake_gather_darkweb)
        monkeypatch.setattr(mon, "_query_leakcheck", _fake_leakcheck_not_found)

        result = _run(mon.run_monitor_check(TEST_EMAIL, target_type="email"))
        assert result["target_type"] == "email"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
