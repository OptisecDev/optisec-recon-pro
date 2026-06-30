"""
Tests for Dark Web & Breach Intelligence (Phase 2B).

All external HTTP calls are mocked via pytest's monkeypatch fixture — these
tests never hit real APIs. Mirrors tests/test_network_intelligence.py's
conventions: plain pytest, async functions driven via asyncio.run(). Only
project-approved test targets are used: test@example.com, example.com,
optisec-recon-pro.onrender.com.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aiohttp
import pytest

import modules.osint.darkweb_intelligence as dw


TEST_EMAIL = "test@example.com"
TEST_DOMAIN = "example.com"
TEST_RENDER_DOMAIN = "optisec-recon-pro.onrender.com"


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
    """Minimal aiohttp.ClientSession stand-in driven by a responder callback.

    `responder(method, url, kwargs) -> _FakeResponse` decides what each
    .get()/.post() call returns, so each test only needs to describe the
    response shape it cares about rather than a real HTTP transport.
    """

    def __init__(self, responder):
        self._responder = responder

    def get(self, url, **kwargs):
        return self._responder("GET", url, kwargs)

    def post(self, url, **kwargs):
        return self._responder("POST", url, kwargs)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


def _patch_session(monkeypatch, responder):
    monkeypatch.setattr(dw.aiohttp, "ClientSession", lambda *a, **kw: _FakeSession(responder))


def _const_responder(resp: _FakeResponse):
    return lambda method, url, kwargs: resp


# ── 1. HIBP ──────────────────────────────────────────────────────────────────

class TestHIBP:
    def test_email_requires_api_key(self, monkeypatch):
        monkeypatch.setattr(dw, "HIBP_API_KEY", "")
        result = _run(dw._query_hibp_email(TEST_EMAIL))
        assert result["available"] is False
        assert "API key" in result["error"]
        assert result["breaches"] == []

    def test_domain_requires_api_key(self, monkeypatch):
        monkeypatch.setattr(dw, "HIBP_API_KEY", "")
        result = _run(dw._query_hibp_domain(TEST_DOMAIN))
        assert result["available"] is False
        assert "API key" in result["error"]
        assert result["breached_accounts"] == {}

    def test_pastes_require_api_key(self, monkeypatch):
        monkeypatch.setattr(dw, "HIBP_API_KEY", "")
        result = _run(dw._query_hibp_pastes(TEST_EMAIL))
        assert result["available"] is False
        assert result["pastes"] == []

    def test_email_parses_breach_list(self, monkeypatch):
        monkeypatch.setattr(dw, "HIBP_API_KEY", "fake-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(200, [
            {"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com", "BreachDate": "2013-10-04",
             "DataClasses": ["Emails", "Passwords"], "PwnCount": 152445165,
             "IsVerified": True, "IsSensitive": False},
        ])))
        result = _run(dw._query_hibp_email(TEST_EMAIL))
        assert result["available"] is True
        assert result["error"] is None
        assert len(result["breaches"]) == 1
        assert result["breaches"][0]["name"] == "Adobe"
        assert result["breaches"][0]["verified"] is True

    def test_email_404_means_no_breaches(self, monkeypatch):
        monkeypatch.setattr(dw, "HIBP_API_KEY", "fake-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(404)))
        result = _run(dw._query_hibp_email(TEST_EMAIL))
        assert result["available"] is True
        assert result["breaches"] == []
        assert result["error"] is None

    def test_email_401_invalid_key(self, monkeypatch):
        monkeypatch.setattr(dw, "HIBP_API_KEY", "bad-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(401)))
        result = _run(dw._query_hibp_email(TEST_EMAIL))
        assert result["available"] is True
        assert "invalid" in result["error"].lower()

    def test_domain_parses_breached_accounts(self, monkeypatch):
        monkeypatch.setattr(dw, "HIBP_API_KEY", "fake-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(200, {"alice": ["Adobe", "LinkedIn"]})))
        result = _run(dw._query_hibp_domain(TEST_DOMAIN))
        assert result["breached_accounts"] == {"alice": ["Adobe", "LinkedIn"]}

    def test_pastes_parses_list(self, monkeypatch):
        monkeypatch.setattr(dw, "HIBP_API_KEY", "fake-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(200, [
            {"Source": "Pastebin", "Id": "abc123", "Title": "leak", "Date": "2020-01-01", "EmailCount": 5},
        ])))
        result = _run(dw._query_hibp_pastes(TEST_EMAIL))
        assert result["pastes"][0]["id"] == "abc123"
        assert result["pastes"][0]["email_count"] == 5


# ── 2. IntelligenceX ───────────────────────────────────────────────────────────

class TestIntelX:
    def test_requires_api_key(self, monkeypatch):
        monkeypatch.setattr(dw, "INTELX_API_KEY", "")
        result = _run(dw._query_intelx(TEST_DOMAIN))
        assert result["available"] is False
        assert "API key" in result["error"]
        assert result["preview"] == []

    def test_search_and_poll_returns_preview(self, monkeypatch):
        monkeypatch.setattr(dw, "INTELX_API_KEY", "fake-key")

        def responder(method, url, kwargs):
            if method == "POST":
                return _FakeResponse(200, {"id": "search-123"})
            return _FakeResponse(200, {
                "status": 1,
                "records": [{"name": "leak.txt", "bucket": "pastes", "date": "2024-01-01"}],
            })

        _patch_session(monkeypatch, responder)
        result = _run(dw._query_intelx(TEST_DOMAIN))
        assert result["available"] is True
        assert result["result_count"] == 1
        assert result["preview"][0]["bucket"] == "pastes"
        assert len(result["preview"][0]["snippet"]) <= 200

    def test_missing_search_id_handled_gracefully(self, monkeypatch):
        monkeypatch.setattr(dw, "INTELX_API_KEY", "fake-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(200, {})))
        result = _run(dw._query_intelx(TEST_DOMAIN))
        assert result["available"] is True
        assert result["result_count"] == 0
        assert "search id" in result["error"]


# ── 3. BreachDirectory ─────────────────────────────────────────────────────────

class TestBreachDirectory:
    def test_requires_api_key(self, monkeypatch):
        monkeypatch.setattr(dw, "RAPIDAPI_KEY", "")
        result = _run(dw._query_breachdirectory(TEST_EMAIL))
        assert result["available"] is False
        assert result["entries"] == []

    def test_parses_entries(self, monkeypatch):
        monkeypatch.setattr(dw, "RAPIDAPI_KEY", "fake-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(200, {
            "result": [{"email": "test@example.com", "password": "hash123", "sources": ["LeakSiteX"]}],
        })))
        result = _run(dw._query_breachdirectory(TEST_EMAIL))
        assert result["entries"][0]["email"] == TEST_EMAIL
        assert result["entries"][0]["password_hash"] == "hash123"

    def test_unauthorized_key_handled(self, monkeypatch):
        monkeypatch.setattr(dw, "RAPIDAPI_KEY", "bad-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(403)))
        result = _run(dw._query_breachdirectory(TEST_EMAIL))
        assert result["available"] is True
        assert result["entries"] == []
        assert result["error"] is not None


# ── 4. Leak-Lookup ─────────────────────────────────────────────────────────────

class TestLeakLookup:
    def test_requires_api_key(self, monkeypatch):
        monkeypatch.setattr(dw, "LEAKLOOKUP_API_KEY", "")
        result = _run(dw._query_leaklookup(TEST_DOMAIN))
        assert result["available"] is False
        assert result["sources_found"] == []

    def test_parses_sources_and_data_types(self, monkeypatch):
        monkeypatch.setattr(dw, "LEAKLOOKUP_API_KEY", "fake-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(200, {
            "error": False,
            "message": {"BreachX": [{"email": "a@b.com", "password": "x"}]},
        })))
        result = _run(dw._query_leaklookup(TEST_DOMAIN))
        assert result["sources_found"] == ["BreachX"]
        assert set(result["data_types"]) == {"email", "password"}

    def test_query_type_detection(self):
        assert dw._leaklookup_query_type(TEST_EMAIL) == "email_address"
        assert dw._leaklookup_query_type("1.2.3.4") == "ip_address"
        assert dw._leaklookup_query_type(TEST_DOMAIN) == "domain"


# ── 5. psbdmp.ws ────────────────────────────────────────────────────────────────

class TestPsbdmp:
    def test_no_results_404(self, monkeypatch):
        _patch_session(monkeypatch, _const_responder(_FakeResponse(404)))
        result = _run(dw._query_psbdmp(TEST_EMAIL))
        assert result["available"] is True
        assert result["pastes"] == []

    def test_parses_results_and_truncates_snippet(self, monkeypatch):
        long_text = "X" * 500

        def responder(method, url, kwargs):
            if "search" in url:
                return _FakeResponse(200, {"data": [{"id": "p1", "time": "2024-01-01"}]})
            return _FakeResponse(200, {"text": long_text})

        _patch_session(monkeypatch, responder)
        result = _run(dw._query_psbdmp(TEST_EMAIL))
        assert len(result["pastes"]) == 1
        assert result["pastes"][0]["id"] == "p1"
        assert len(result["pastes"][0]["snippet"]) == 200
        assert result["pastes"][0]["url"] == "https://pastebin.com/p1"

    def test_caps_at_max_results(self, monkeypatch):
        many = [{"id": f"p{i}", "time": "2024-01-01"} for i in range(20)]

        def responder(method, url, kwargs):
            if "search" in url:
                return _FakeResponse(200, {"data": many})
            return _FakeResponse(200, {"text": ""})

        _patch_session(monkeypatch, responder)
        result = _run(dw._query_psbdmp(TEST_EMAIL))
        assert len(result["pastes"]) == dw._PSBDMP_MAX_RESULTS


# ── 6. GitHub Exposed Secrets ──────────────────────────────────────────────────

class TestGithubSecrets:
    def test_aggregates_across_keywords(self, monkeypatch):
        def responder(method, url, kwargs):
            keyword = kwargs["params"]["q"].split()[-1]
            return _FakeResponse(200, {"items": [{
                "repository": {"full_name": f"org/repo-{keyword}"},
                "path": "config.py",
                "html_url": f"https://github.com/org/repo-{keyword}/blob/main/config.py",
                "text_matches": [{"fragment": f"{keyword} = 'leaked'"}],
            }]})

        _patch_session(monkeypatch, responder)
        result = _run(dw._query_github_secrets(TEST_DOMAIN))
        assert result["available"] is True
        assert len(result["exposures"]) == len(dw._GITHUB_SECRET_KEYWORDS)
        found_keywords = {e["keyword"] for e in result["exposures"]}
        assert found_keywords == set(dw._GITHUB_SECRET_KEYWORDS)

    def test_rate_limit_does_not_crash(self, monkeypatch):
        _patch_session(monkeypatch, _const_responder(_FakeResponse(403)))
        result = _run(dw._query_github_secrets(TEST_DOMAIN))
        assert result["available"] is True
        assert result["exposures"] == []
        assert result["error"] is not None


# ── 7. Threat Actor Intelligence ──────────────────────────────────────────────

class TestThreatActors:
    def test_requires_api_key(self, monkeypatch):
        monkeypatch.setattr(dw, "OTX_API_KEY", "")
        result = _run(dw._query_threat_actors(TEST_DOMAIN))
        assert result["available"] is False
        assert result["threat_actors"] == []

    def test_parses_pulses(self, monkeypatch):
        monkeypatch.setattr(dw, "OTX_API_KEY", "fake-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(200, {
            "pulse_info": {
                "count": 2,
                "pulses": [
                    {"name": "Campaign Alpha", "adversary": "APT99",
                     "malware_families": [{"display_name": "EvilRAT"}]},
                    {"name": "Campaign Beta", "adversary": "APT99", "malware_families": []},
                ],
            },
        })))
        result = _run(dw._query_threat_actors(TEST_DOMAIN))
        assert result["threat_actors"] == ["APT99"]
        assert result["malware_families"] == ["EvilRAT"]
        assert set(result["campaigns"]) == {"Campaign Alpha", "Campaign Beta"}
        assert result["pulse_count"] == 2

    def test_404_means_no_pulses(self, monkeypatch):
        monkeypatch.setattr(dw, "OTX_API_KEY", "fake-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(404)))
        result = _run(dw._query_threat_actors(TEST_DOMAIN))
        assert result["available"] is True
        assert result["threat_actors"] == []

    def test_indicator_url_picks_ip_vs_domain(self):
        assert "IPv4" in dw._otx_indicator_url("1.2.3.4")
        assert "domain" in dw._otx_indicator_url(TEST_DOMAIN)
        assert "domain" in dw._otx_indicator_url(TEST_EMAIL)


# ── 8. Dark Web Exposure Score ─────────────────────────────────────────────────

class TestExposureLevel:
    def test_clean_band(self):
        assert dw._exposure_level(0) == "Clean"
        assert dw._exposure_level(20) == "Clean"

    def test_exposed_band(self):
        assert dw._exposure_level(21) == "Exposed"
        assert dw._exposure_level(50) == "Exposed"

    def test_compromised_band(self):
        assert dw._exposure_level(51) == "Compromised"
        assert dw._exposure_level(80) == "Compromised"

    def test_critical_band(self):
        assert dw._exposure_level(81) == "Critical"
        assert dw._exposure_level(100) == "Critical"


class TestCalculateDarkwebExposureScore:
    def test_empty_results_score_zero_clean(self):
        result = dw.calculate_darkweb_exposure_score({})
        assert result["score"] == 0
        assert result["exposure_level"] == "Clean"
        assert result["breakdown"] == []
        assert len(result["recommendations"]) == 1

    def test_verified_breach_adds_20(self):
        result = dw.calculate_darkweb_exposure_score({"breaches": [{"name": "Adobe", "verified": True}]})
        assert result["score"] == 20

    def test_unverified_breach_adds_nothing(self):
        result = dw.calculate_darkweb_exposure_score({"breaches": [{"name": "Adobe", "verified": False}]})
        assert result["score"] == 0

    def test_paste_adds_10_each(self):
        result = dw.calculate_darkweb_exposure_score({"pastes": [{"id": "p1"}, {"id": "p2"}]})
        assert result["score"] == 20

    def test_github_exposure_adds_25_each(self):
        result = dw.calculate_darkweb_exposure_score({"github_exposures": [{"html_url": "x"}]})
        assert result["score"] == 25

    def test_threat_actor_adds_30_each(self):
        result = dw.calculate_darkweb_exposure_score({"threat_actors": ["APT99"]})
        assert result["score"] == 30

    def test_score_capped_at_100(self):
        result = dw.calculate_darkweb_exposure_score({
            "breaches": [{"verified": True}] * 5,
            "github_exposures": [{"html_url": "x"}] * 5,
            "threat_actors": ["A", "B", "C"],
        })
        assert result["score"] == 100
        assert result["exposure_level"] == "Critical"

    def test_breakdown_entries_have_reason_and_points(self):
        result = dw.calculate_darkweb_exposure_score({"threat_actors": ["APT99"]})
        for entry in result["breakdown"]:
            assert "reason" in entry
            assert "points" in entry

    def test_recommendations_mention_relevant_action(self):
        result = dw.calculate_darkweb_exposure_score({"github_exposures": [{"html_url": "x"}]})
        assert any("credential" in r.lower() or "rotate" in r.lower() for r in result["recommendations"])

    def test_combined_realistic_scenario(self):
        result = dw.calculate_darkweb_exposure_score({
            "breaches": [{"verified": True}],
            "pastes": [{"id": "p1"}],
            "threat_actors": ["APT99"],
        })
        # verified breach (20) + 1 paste (10) + 1 threat actor (30) = 60
        assert result["score"] == 60
        assert result["exposure_level"] == "Compromised"


# ── 9. Orchestrator ─────────────────────────────────────────────────────────────

async def _ok(**fields):
    base = {"available": True, "error": None}
    base.update(fields)
    return base


class TestGatherDarkwebIntelligence:
    def _patch_all_sources(self, monkeypatch, *, hibp_email=None, hibp_domain=None,
                            hibp_pastes=None, psbdmp=None, github=None, threat_actors=None):
        monkeypatch.setattr(dw, "_query_intelx", lambda t: _ok(source="intelx", result_count=0, preview=[]))
        monkeypatch.setattr(dw, "_query_breachdirectory", lambda t: _ok(source="breachdirectory", entries=[]))
        monkeypatch.setattr(dw, "_query_leaklookup", lambda t: _ok(source="leaklookup", sources_found=[], data_types=[]))
        monkeypatch.setattr(dw, "_query_threat_actors",
                             lambda t: threat_actors or _ok(source="threat_actors", threat_actors=[],
                                                             malware_families=[], campaigns=[], pulse_count=0))
        monkeypatch.setattr(dw, "_query_hibp_email",
                             lambda t: hibp_email or _ok(source="hibp_email", breaches=[]))
        monkeypatch.setattr(dw, "_query_hibp_domain",
                             lambda t: hibp_domain or _ok(source="hibp_domain", breached_accounts={}))
        monkeypatch.setattr(dw, "_query_hibp_pastes",
                             lambda t: hibp_pastes or _ok(source="hibp_pastes", pastes=[]))
        monkeypatch.setattr(dw, "_query_psbdmp", lambda t: psbdmp or _ok(source="psbdmp", pastes=[]))
        monkeypatch.setattr(dw, "_query_github_secrets",
                             lambda t: github or _ok(source="github_secrets", exposures=[]))

    def test_email_target_structure(self, monkeypatch):
        self._patch_all_sources(monkeypatch)
        result = _run(dw.gather_darkweb_intelligence(TEST_EMAIL))
        assert result["target"] == TEST_EMAIL
        assert result["target_type"] == "email"
        for key in ("breaches", "pastes", "github_exposures", "threat_actors"):
            assert key in result and isinstance(result[key], list)
        assert "exposure" in result
        assert result["exposure"]["score"] == 0

    def test_domain_target_structure(self, monkeypatch):
        self._patch_all_sources(monkeypatch)
        result = _run(dw.gather_darkweb_intelligence(TEST_DOMAIN))
        assert result["target"] == TEST_DOMAIN
        assert result["target_type"] == "domain"

    def test_render_domain_target_structure(self, monkeypatch):
        self._patch_all_sources(monkeypatch)
        result = _run(dw.gather_darkweb_intelligence(TEST_RENDER_DOMAIN))
        assert result["target"] == TEST_RENDER_DOMAIN
        assert result["target_type"] == "domain"

    def test_combines_hibp_email_breaches(self, monkeypatch):
        self._patch_all_sources(
            monkeypatch,
            hibp_email=_ok(source="hibp_email", breaches=[{"name": "Adobe", "verified": True}]),
        )
        result = _run(dw.gather_darkweb_intelligence(TEST_EMAIL))
        assert len(result["breaches"]) == 1
        assert result["exposure"]["score"] == 20

    def test_flattens_hibp_domain_breached_accounts(self, monkeypatch):
        self._patch_all_sources(
            monkeypatch,
            hibp_domain=_ok(source="hibp_domain", breached_accounts={"alice": ["Adobe", "LinkedIn"]}),
        )
        result = _run(dw.gather_darkweb_intelligence(TEST_DOMAIN))
        assert len(result["breaches"]) == 2
        names = {b["name"] for b in result["breaches"]}
        assert names == {"Adobe", "LinkedIn"}
        # /breacheddomain breaches carry no verification status -> no score points
        assert result["exposure"]["score"] == 0

    def test_combines_pastes_from_hibp_and_psbdmp(self, monkeypatch):
        self._patch_all_sources(
            monkeypatch,
            hibp_pastes=_ok(source="hibp_pastes", pastes=[{"id": "h1"}]),
            psbdmp=_ok(source="psbdmp", pastes=[{"id": "p1"}]),
        )
        result = _run(dw.gather_darkweb_intelligence(TEST_EMAIL))
        assert len(result["pastes"]) == 2

    def test_include_pastes_false_skips_paste_sources(self, monkeypatch):
        calls: list[str] = []
        self._patch_all_sources(monkeypatch)
        monkeypatch.setattr(dw, "_query_psbdmp", lambda t: calls.append("psbdmp") or _ok(source="psbdmp", pastes=[]))
        monkeypatch.setattr(dw, "_query_hibp_pastes",
                             lambda t: calls.append("hibp_pastes") or _ok(source="hibp_pastes", pastes=[]))
        _run(dw.gather_darkweb_intelligence(TEST_EMAIL, include_pastes=False))
        assert "psbdmp" not in calls
        assert "hibp_pastes" not in calls

    def test_include_github_false_skips_github(self, monkeypatch):
        calls: list[str] = []
        self._patch_all_sources(monkeypatch)
        monkeypatch.setattr(dw, "_query_github_secrets",
                             lambda t: calls.append("github") or _ok(source="github_secrets", exposures=[]))
        _run(dw.gather_darkweb_intelligence(TEST_DOMAIN, include_github=False))
        assert "github" not in calls

    def test_no_api_keys_degrades_gracefully(self, monkeypatch):
        """With every key unset, the keyed sources short-circuit to
        available=False on their own (no network call) — exercise the real
        _query_* functions here rather than the canned stand-ins. Only the
        keyless, network-touching sources (psbdmp/GitHub) are mocked, so
        this test never hits the real network either way."""
        monkeypatch.setattr(dw, "HIBP_API_KEY", "")
        monkeypatch.setattr(dw, "INTELX_API_KEY", "")
        monkeypatch.setattr(dw, "RAPIDAPI_KEY", "")
        monkeypatch.setattr(dw, "LEAKLOOKUP_API_KEY", "")
        monkeypatch.setattr(dw, "OTX_API_KEY", "")
        monkeypatch.setattr(dw, "_query_psbdmp", lambda t: _ok(source="psbdmp", pastes=[]))
        monkeypatch.setattr(dw, "_query_github_secrets", lambda t: _ok(source="github_secrets", exposures=[]))

        result = _run(dw.gather_darkweb_intelligence(TEST_EMAIL))
        assert result["intelx"]["available"] is False
        assert result["breachdirectory"]["available"] is False
        assert result["leaklookup"]["available"] is False
        assert result["threat_actor_detail"]["available"] is False
        assert result["exposure"]["score"] == 0
        assert result["exposure"]["exposure_level"] == "Clean"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
