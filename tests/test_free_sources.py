"""
Tests for the free-tier OSINT sources added to unified_engine.py:
VirusTotal, AbuseIPDB, FullHunt, LeakCheck, SecurityTrails, URLScan.io and
Google Safe Browsing, plus the enriched Wayback Machine summary.

All external HTTP calls are mocked via monkeypatch — these tests never hit
real APIs. Mirrors tests/test_darkweb_intelligence.py's _FakeResponse/
_FakeSession conventions. Only project-approved test targets are used:
example.com, 1.1.1.1, 8.8.8.8, test@example.com.
"""

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aiohttp
import pytest

import modules.osint.unified_engine as u
from modules.osint.confidence_engine import SOURCE_RELIABILITY


TEST_DOMAIN = "example.com"
TEST_IP_1 = "1.1.1.1"
TEST_IP_2 = "8.8.8.8"
TEST_EMAIL = "test@example.com"


def _run(coro):
    return asyncio.run(coro)


# ── Fake aiohttp plumbing — no real network calls ────────────────────────────

class _FakeResponse:
    def __init__(self, status=200, json_data=None, text_data=None):
        self.status = status
        self._json_data = {} if json_data is None else json_data
        self._text_data = text_data

    async def json(self):
        return self._json_data

    async def text(self):
        if self._text_data is not None:
            return self._text_data
        return json.dumps(self._json_data)

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

    def post(self, url, **kwargs):
        return self._responder("POST", url, kwargs)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


def _patch_session(monkeypatch, responder):
    monkeypatch.setattr(u.aiohttp, "ClientSession", lambda *a, **kw: _FakeSession(responder))


def _const_responder(resp: _FakeResponse):
    return lambda method, url, kwargs: resp


# ── 1. VirusTotal ──────────────────────────────────────────────────────────────

class TestVirusTotal:
    def test_requires_api_key(self, monkeypatch):
        monkeypatch.setattr(u, "VT_API_KEY", "")
        result = _run(u._query_virustotal(TEST_DOMAIN, "domain"))
        assert result["available"] is False
        assert "API key" in result["error"]

    def test_parses_domain_stats(self, monkeypatch):
        monkeypatch.setattr(u, "VT_API_KEY", "fake-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(200, {
            "data": {"attributes": {
                "reputation": -10,
                "total_votes": {"harmless": 2, "malicious": 5},
                "categories": {"vendorA": "phishing"},
                "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 10},
            }},
        })))
        result = _run(u._query_virustotal(TEST_DOMAIN, "domain"))
        assert result["available"] is True
        assert result["reputation"] == -10
        assert result["malicious_votes"] == 5
        assert result["last_analysis_stats"]["malicious"] == 5
        assert result["categories"] == {"vendorA": "phishing"}

    def test_parses_ip_target(self, monkeypatch):
        monkeypatch.setattr(u, "VT_API_KEY", "fake-key")
        captured = {}

        def responder(method, url, kwargs):
            captured["url"] = url
            return _FakeResponse(200, {"data": {"attributes": {}}})

        _patch_session(monkeypatch, responder)
        _run(u._query_virustotal(TEST_IP_1, "ip"))
        assert "ip_addresses" in captured["url"]
        assert TEST_IP_1 in captured["url"]

    def test_404_returns_empty_no_error(self, monkeypatch):
        monkeypatch.setattr(u, "VT_API_KEY", "fake-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(404)))
        result = _run(u._query_virustotal(TEST_DOMAIN, "domain"))
        assert result["available"] is True
        assert result["error"] is None
        assert result["last_analysis_stats"] == {}

    def test_401_invalid_key(self, monkeypatch):
        monkeypatch.setattr(u, "VT_API_KEY", "bad-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(401)))
        result = _run(u._query_virustotal(TEST_DOMAIN, "domain"))
        assert result["available"] is True
        assert "invalid" in result["error"].lower()

    def test_to_findings_scales_severity_with_malicious_count(self):
        clean = u._virustotal_to_findings({
            "available": True, "error": None, "target": TEST_DOMAIN,
            "last_analysis_stats": {"malicious": 0, "suspicious": 0},
        })
        assert clean[0]["severity"] == "info"

        suspicious = u._virustotal_to_findings({
            "available": True, "error": None, "target": TEST_DOMAIN,
            "last_analysis_stats": {"malicious": 0, "suspicious": 2},
        })
        assert suspicious[0]["severity"] == "medium"

        high = u._virustotal_to_findings({
            "available": True, "error": None, "target": TEST_DOMAIN,
            "last_analysis_stats": {"malicious": 1, "suspicious": 0},
        })
        assert high[0]["severity"] == "high"

        critical = u._virustotal_to_findings({
            "available": True, "error": None, "target": TEST_DOMAIN,
            "last_analysis_stats": {"malicious": 5, "suspicious": 0},
        })
        assert critical[0]["severity"] == "critical"

    def test_to_findings_empty_when_unavailable(self):
        assert u._virustotal_to_findings({"available": False, "error": "x"}) == []

    def test_run_virustotal_degrades_without_key(self, monkeypatch):
        monkeypatch.setattr(u, "VT_API_KEY", "")
        result = _run(u._run_virustotal(TEST_DOMAIN, "domain"))
        assert result["source"] == "virustotal"
        assert result["available"] is False
        assert result["results"] == []


# ── 2. AbuseIPDB ───────────────────────────────────────────────────────────────

class TestAbuseIPDB:
    def test_requires_api_key(self, monkeypatch):
        monkeypatch.setattr(u, "ABUSEIPDB_API_KEY", "")
        result = _run(u._query_abuseipdb(TEST_IP_1))
        assert result["available"] is False
        assert "API key" in result["error"]

    def test_parses_check_response(self, monkeypatch):
        monkeypatch.setattr(u, "ABUSEIPDB_API_KEY", "fake-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(200, {
            "data": {
                "abuseConfidenceScore": 80,
                "totalReports": 42,
                "lastReportedAt": "2024-01-01T00:00:00+00:00",
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "Cloudflare",
                "countryCode": "US",
            },
        })))
        result = _run(u._query_abuseipdb(TEST_IP_1))
        assert result["abuse_confidence_score"] == 80
        assert result["total_reports"] == 42
        assert result["isp"] == "Cloudflare"
        assert result["country_code"] == "US"

    def test_401_invalid_key(self, monkeypatch):
        monkeypatch.setattr(u, "ABUSEIPDB_API_KEY", "bad-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(401)))
        result = _run(u._query_abuseipdb(TEST_IP_1))
        assert result["available"] is True
        assert "invalid" in result["error"].lower()

    def test_to_findings_severity_bands(self):
        for score, expected in [(80, "critical"), (60, "high"), (30, "medium"), (5, "info")]:
            findings = u._abuseipdb_to_findings({
                "available": True, "error": None, "target": TEST_IP_1,
                "abuse_confidence_score": score,
            })
            assert findings[0]["severity"] == expected

    def test_to_findings_empty_without_score(self):
        assert u._abuseipdb_to_findings({"available": True, "error": None, "abuse_confidence_score": None}) == []


# ── 3. FullHunt ────────────────────────────────────────────────────────────────

class TestFullHunt:
    def test_requires_api_key(self, monkeypatch):
        monkeypatch.setattr(u, "FULLHUNT_API_KEY", "")
        result = _run(u._query_fullhunt(TEST_DOMAIN))
        assert result["available"] is False
        assert result["subdomains"] == []

    def test_parses_plain_string_hosts(self, monkeypatch):
        monkeypatch.setattr(u, "FULLHUNT_API_KEY", "fake-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(200, {
            "hosts": ["api.example.com", "www.example.com"],
            "hosts_count": 2,
        })))
        result = _run(u._query_fullhunt(TEST_DOMAIN))
        assert result["subdomains"] == ["api.example.com", "www.example.com"]
        assert result["hosts_count"] == 2

    def test_parses_dict_hosts_with_ports_and_tech(self, monkeypatch):
        monkeypatch.setattr(u, "FULLHUNT_API_KEY", "fake-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(200, {
            "hosts": [{"host": "api.example.com", "open_ports": [443, 80], "technologies": ["nginx"]}],
        })))
        result = _run(u._query_fullhunt(TEST_DOMAIN))
        assert result["subdomains"] == ["api.example.com"]
        assert result["ports"] == [80, 443]
        assert result["technologies"] == ["nginx"]

    def test_401_invalid_key(self, monkeypatch):
        monkeypatch.setattr(u, "FULLHUNT_API_KEY", "bad-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(401)))
        result = _run(u._query_fullhunt(TEST_DOMAIN))
        assert result["available"] is True
        assert "invalid" in result["error"].lower()

    def test_to_findings_subdomains_and_ports(self):
        findings = u._fullhunt_to_findings({
            "available": True, "error": None, "target": TEST_DOMAIN,
            "subdomains": ["a.example.com"], "ports": [22],
        })
        types = {f["type"] for f in findings}
        assert types == {"subdomain", "open_port"}


# ── 4. LeakCheck ───────────────────────────────────────────────────────────────

class TestLeakCheck:
    def test_works_keyless_via_public_endpoint(self, monkeypatch):
        monkeypatch.setattr(u, "LEAKCHECK_API_KEY", "")
        captured = {}

        def responder(method, url, kwargs):
            captured["url"] = url
            return _FakeResponse(200, {"success": True, "found": True,
                                        "sources": [{"name": "BreachX"}], "fields": ["email", "password"]})

        _patch_session(monkeypatch, responder)
        result = _run(u._query_leakcheck(TEST_EMAIL))
        assert "public" in captured["url"]
        assert result["available"] is True
        assert result["found"] is True
        assert result["sources"] == ["BreachX"]
        assert set(result["fields"]) == {"email", "password"}

    def test_uses_pro_endpoint_when_key_set(self, monkeypatch):
        monkeypatch.setattr(u, "LEAKCHECK_API_KEY", "fake-key")
        captured = {}

        def responder(method, url, kwargs):
            captured["url"] = url
            return _FakeResponse(200, {"success": True, "found": False})

        _patch_session(monkeypatch, responder)
        result = _run(u._query_leakcheck(TEST_EMAIL))
        assert "v2/query" in captured["url"]
        assert result["found"] is False

    def test_not_found(self, monkeypatch):
        monkeypatch.setattr(u, "LEAKCHECK_API_KEY", "")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(200, {"success": True, "found": False})))
        result = _run(u._query_leakcheck(TEST_DOMAIN))
        assert result["found"] is False

    def test_401_invalid_key(self, monkeypatch):
        monkeypatch.setattr(u, "LEAKCHECK_API_KEY", "bad-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(401)))
        result = _run(u._query_leakcheck(TEST_EMAIL))
        assert result["available"] is True
        assert "invalid" in result["error"].lower()

    def test_to_findings_only_when_found(self):
        assert u._leakcheck_to_findings({"available": True, "error": None, "found": False}) == []
        findings = u._leakcheck_to_findings({
            "available": True, "error": None, "found": True, "target": TEST_EMAIL,
            "sources": ["BreachX"], "fields": ["password"],
        })
        assert findings[0]["type"] == "leak_exposure"
        assert findings[0]["severity"] == "high"


# ── 5. SecurityTrails ──────────────────────────────────────────────────────────

class TestSecurityTrails:
    def test_requires_api_key(self, monkeypatch):
        monkeypatch.setattr(u, "SECURITYTRAILS_API_KEY", "")
        result = _run(u._query_securitytrails(TEST_DOMAIN))
        assert result["available"] is False
        assert result["current_dns"] == {}

    def test_parses_domain_overview(self, monkeypatch):
        monkeypatch.setattr(u, "SECURITYTRAILS_API_KEY", "fake-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(200, {
            "current_dns": {"a": {"values": [{"ip": "93.184.216.34"}]}},
            "subdomain_count": 12,
            "alexa_rank": 5000,
            "whois": {"email": "admin@example.com"},
        })))
        result = _run(u._query_securitytrails(TEST_DOMAIN))
        assert result["subdomain_count"] == 12
        assert result["alexa_rank"] == 5000
        assert result["whois_email"] == "admin@example.com"
        assert result["current_dns"]["a"]["values"][0]["ip"] == "93.184.216.34"

    def test_403_invalid_key(self, monkeypatch):
        monkeypatch.setattr(u, "SECURITYTRAILS_API_KEY", "bad-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(403)))
        result = _run(u._query_securitytrails(TEST_DOMAIN))
        assert result["available"] is True
        assert "invalid" in result["error"].lower()

    def test_to_findings_dns_and_whois_email(self):
        findings = u._securitytrails_to_findings({
            "available": True, "error": None,
            "current_dns": {"a": {"values": [{"ip": "1.2.3.4"}]}},
            "whois_email": "admin@example.com",
        })
        types = {f["type"] for f in findings}
        assert "dns_record" in types
        assert "email" in types


# ── 6. URLScan.io ──────────────────────────────────────────────────────────────

class TestURLScan:
    def test_works_without_any_key(self, monkeypatch):
        _patch_session(monkeypatch, _const_responder(_FakeResponse(200, {"results": []})))
        result = _run(u._query_urlscan(TEST_DOMAIN, "domain"))
        assert result["available"] is True
        assert result["error"] is None

    def test_parses_search_results(self, monkeypatch):
        _patch_session(monkeypatch, _const_responder(_FakeResponse(200, {
            "results": [{
                "page": {"url": "http://example.com/", "ip": "93.184.216.34", "server": "ECS"},
                "task": {"uuid": "abc-123", "time": "2024-01-01T00:00:00"},
                "screenshot": "https://urlscan.io/screenshots/abc-123.png",
                "verdicts": {"overall": {"malicious": False}},
            }],
        })))
        result = _run(u._query_urlscan(TEST_DOMAIN, "domain"))
        assert len(result["scans"]) == 1
        assert result["scans"][0]["scan_id"] == "abc-123"
        assert result["ips"] == ["93.184.216.34"]

    def test_ip_target_uses_ip_query(self, monkeypatch):
        captured = {}

        def responder(method, url, kwargs):
            captured["params"] = kwargs.get("params")
            return _FakeResponse(200, {"results": []})

        _patch_session(monkeypatch, responder)
        _run(u._query_urlscan(TEST_IP_2, "ip"))
        assert captured["params"]["q"] == f"ip:{TEST_IP_2}"

    def test_rate_limited(self, monkeypatch):
        _patch_session(monkeypatch, _const_responder(_FakeResponse(429)))
        result = _run(u._query_urlscan(TEST_DOMAIN, "domain"))
        assert result["available"] is True
        assert "rate limit" in result["error"].lower()

    def test_to_findings_malicious_verdict_is_high(self):
        findings = u._urlscan_to_findings({
            "available": True, "error": None, "target": TEST_DOMAIN,
            "scans": [{"url": "http://example.com/", "verdict_malicious": True}],
            "ips": [],
        })
        assert findings[0]["severity"] == "high"


# ── 7. Google Safe Browsing ────────────────────────────────────────────────────

class TestGoogleSafeBrowsing:
    def test_requires_api_key(self, monkeypatch):
        monkeypatch.setattr(u, "GOOGLE_SAFEBROWSING_API_KEY", "")
        result = _run(u._query_google_safebrowsing(f"http://{TEST_DOMAIN}"))
        assert result["available"] is False
        assert "API key" in result["error"]

    def test_clean_url_no_matches(self, monkeypatch):
        monkeypatch.setattr(u, "GOOGLE_SAFEBROWSING_API_KEY", "fake-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(200, {})))
        result = _run(u._query_google_safebrowsing(f"http://{TEST_DOMAIN}"))
        assert result["threats"] == []
        assert result["is_safe"] is True

    def test_threat_match_found(self, monkeypatch):
        monkeypatch.setattr(u, "GOOGLE_SAFEBROWSING_API_KEY", "fake-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(200, {
            "matches": [{"threatType": "MALWARE"}, {"threatType": "SOCIAL_ENGINEERING"}],
        })))
        result = _run(u._query_google_safebrowsing(f"http://{TEST_DOMAIN}"))
        assert set(result["threats"]) == {"MALWARE", "SOCIAL_ENGINEERING"}
        assert result["is_safe"] is False

    def test_invalid_key_handled(self, monkeypatch):
        monkeypatch.setattr(u, "GOOGLE_SAFEBROWSING_API_KEY", "bad-key")
        _patch_session(monkeypatch, _const_responder(_FakeResponse(403)))
        result = _run(u._query_google_safebrowsing(f"http://{TEST_DOMAIN}"))
        assert result["available"] is True
        assert "invalid" in result["error"].lower()

    def test_to_findings_critical_per_threat(self):
        findings = u._safebrowsing_to_findings({
            "available": True, "error": None, "target": f"http://{TEST_DOMAIN}",
            "threats": ["MALWARE"],
        })
        assert findings[0]["severity"] == "critical"
        assert findings[0]["threat_type"] == "MALWARE"

    def test_run_google_safebrowsing_builds_url_from_bare_domain(self, monkeypatch):
        monkeypatch.setattr(u, "GOOGLE_SAFEBROWSING_API_KEY", "")
        result = _run(u._run_google_safebrowsing(TEST_DOMAIN))
        assert result["source"] == "google_safebrowsing"
        assert result["available"] is False


# ── 8. Wayback Machine enrichment ──────────────────────────────────────────────

class TestWaybackSummary:
    def test_extracts_oldest_newest_and_total(self):
        sample = json.dumps([
            ["original", "timestamp"],
            ["http://api.example.com/admin", "20200101000000"],
            ["https://www.example.com/", "20230615120000"],
            ["http://old.example.com/legacy", "20150101000000"],
        ])
        summary = u._wayback_summary(sample)
        assert summary["oldest_snapshot"] == "20150101000000"
        assert summary["newest_snapshot"] == "20230615120000"
        assert summary["total_snapshots"] == 3

    def test_ranks_top_paths_by_frequency(self):
        sample = json.dumps([
            ["original", "timestamp"],
            ["http://example.com/admin", "20200101000000"],
            ["http://example.com/admin", "20200102000000"],
            ["http://example.com/login", "20200103000000"],
        ])
        summary = u._wayback_summary(sample)
        assert summary["top_paths"][0] == {"path": "/admin", "count": 2}

    def test_header_only_returns_empty_summary(self):
        summary = u._wayback_summary(json.dumps([["original", "timestamp"]]))
        assert summary["total_snapshots"] == 0
        assert summary["oldest_snapshot"] is None

    def test_malformed_json_returns_empty_summary(self):
        summary = u._wayback_summary("not json")
        assert summary == {"oldest_snapshot": None, "newest_snapshot": None,
                            "total_snapshots": 0, "top_paths": []}

    def test_parse_wayback_cdx_still_handles_single_column_rows(self):
        """Backward compatibility: rows with only `original` (no timestamp)
        must still parse, since the function predates the timestamp field."""
        sample = json.dumps([["original"], ["http://api.example.com/path"]])
        results = u._parse_wayback_cdx(sample)
        assert results[0]["value"] == "api.example.com"
        assert "timestamp" not in results[0]

    def test_parse_wayback_cdx_attaches_timestamp_when_present(self):
        sample = json.dumps([["original", "timestamp"], ["http://api.example.com/path", "20240101000000"]])
        results = u._parse_wayback_cdx(sample)
        assert results[0]["timestamp"] == "20240101000000"


class TestRunWayback:
    def test_merges_results_and_summary(self, monkeypatch):
        sample = json.dumps([
            ["original", "timestamp"],
            ["http://api.example.com/admin", "20200101000000"],
        ])
        monkeypatch.setattr(u, "_fetch_wayback_raw", lambda domain: asyncio.sleep(0, result=sample))
        result = _run(u._run_wayback(TEST_DOMAIN))
        assert result["source"] == "wayback"
        assert result["available"] is True
        assert len(result["results"]) == 1
        assert result["total_snapshots"] == 1
        assert result["oldest_snapshot"] == "20200101000000"

    def test_timeout_returns_graceful_error(self, monkeypatch):
        async def _hang(domain):
            await asyncio.sleep(10)

        monkeypatch.setattr(u, "_fetch_wayback_raw", _hang)
        monkeypatch.setitem(u._TOOL_TIMEOUTS, "wayback", 0.01)
        result = _run(u._run_wayback(TEST_DOMAIN))
        assert result["available"] is True
        assert "timed out" in result["error"]
        assert result["results"] == []


# ── 9. Sources status ──────────────────────────────────────────────────────────

class TestSourcesStatusFreeSources:
    def test_includes_all_new_sources(self):
        names = {s["source"] for s in u.get_sources_status()}
        for name in ("virustotal", "abuseipdb", "fullhunt", "leakcheck",
                     "securitytrails", "urlscan", "google_safebrowsing"):
            assert name in names

    def test_keyed_sources_report_api_key_configured(self, monkeypatch):
        monkeypatch.setattr(u, "os", u.os)  # sanity: os module is the real one
        monkeypatch.delenv("VT_API_KEY", raising=False)
        statuses = {s["source"]: s for s in u.get_sources_status()}
        assert statuses["virustotal"]["api_key_configured"] is False
        assert statuses["virustotal"]["requires_api_key"] is True
        assert "signup_url" in statuses["virustotal"]
        assert "free_tier_limit" in statuses["virustotal"]

    def test_keyless_sources_do_not_require_key(self):
        statuses = {s["source"]: s for s in u.get_sources_status()}
        assert statuses["urlscan"]["requires_api_key"] is False
        assert statuses["leakcheck"]["requires_api_key"] is False

    def test_api_key_configured_true_when_env_set(self, monkeypatch):
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "some-key")
        statuses = {s["source"]: s for s in u.get_sources_status()}
        assert statuses["abuseipdb"]["api_key_configured"] is True


# ── 10. Confidence scoring ──────────────────────────────────────────────────────

class TestConfidenceReliability:
    def test_new_sources_have_expected_weights(self):
        assert SOURCE_RELIABILITY["virustotal"] == 92
        assert SOURCE_RELIABILITY["abuseipdb"] == 88
        assert SOURCE_RELIABILITY["fullhunt"] == 85
        assert SOURCE_RELIABILITY["urlscan"] == 87
        assert SOURCE_RELIABILITY["securitytrails"] == 90
        assert SOURCE_RELIABILITY["leakcheck"] == 82
        assert SOURCE_RELIABILITY["google_safebrowsing"] == 95


# ── 11. search_unified() wiring ─────────────────────────────────────────────────

async def _ok(source, **fields):
    base = {"source": source, "available": True, "results": []}
    base.update(fields)
    return base


class TestSearchUnifiedWiring:
    """Confirm each target type's task list includes the new free sources,
    without making any real network calls — every _run_* used by
    search_unified() is replaced with a fast stand-in."""

    def _patch_all_runners(self, monkeypatch):
        for name in ("_run_amass", "_run_crtsh", "_run_wayback", "_run_dns_full",
                     "_run_whois", "_run_network_intel", "_run_darkweb_intel",
                     "_run_holehe", "_run_maigret"):
            monkeypatch.setattr(u, name, lambda *a, **kw: _ok(name.replace("_run_", "")))
        monkeypatch.setattr(u, "_run_theharvester", lambda *a, **kw: _ok("theHarvester"))
        monkeypatch.setattr(u, "_run_virustotal", lambda *a, **kw: _ok("virustotal"))
        monkeypatch.setattr(u, "_run_urlscan", lambda *a, **kw: _ok("urlscan"))
        monkeypatch.setattr(u, "_run_securitytrails", lambda *a, **kw: _ok("securitytrails"))
        monkeypatch.setattr(u, "_run_fullhunt", lambda *a, **kw: _ok("fullhunt"))
        monkeypatch.setattr(u, "_run_google_safebrowsing", lambda *a, **kw: _ok("google_safebrowsing"))
        monkeypatch.setattr(u, "_run_abuseipdb", lambda *a, **kw: _ok("abuseipdb"))
        monkeypatch.setattr(u, "_run_leakcheck", lambda *a, **kw: _ok("leakcheck"))

    def test_domain_includes_new_sources(self, monkeypatch):
        self._patch_all_runners(monkeypatch)
        key = "__test_free_domain__"
        u._rate_store.pop(key, None)
        result = _run(u.search_unified(TEST_DOMAIN, "domain", key))
        names = {s["source"] for s in result["sources"]}
        for expected in ("virustotal", "urlscan", "securitytrails", "fullhunt", "google_safebrowsing"):
            assert expected in names

    def test_ip_includes_new_sources(self, monkeypatch):
        self._patch_all_runners(monkeypatch)
        key = "__test_free_ip__"
        u._rate_store.pop(key, None)
        result = _run(u.search_unified(TEST_IP_1, "ip", key))
        names = {s["source"] for s in result["sources"]}
        for expected in ("virustotal", "abuseipdb", "urlscan"):
            assert expected in names
        assert "google_safebrowsing" not in names

    def test_email_includes_leakcheck(self, monkeypatch):
        self._patch_all_runners(monkeypatch)
        key = "__test_free_email__"
        u._rate_store.pop(key, None)
        result = _run(u.search_unified(TEST_EMAIL, "email", key))
        names = {s["source"] for s in result["sources"]}
        assert "leakcheck" in names

    def test_username_unaffected(self, monkeypatch):
        self._patch_all_runners(monkeypatch)
        key = "__test_free_username__"
        u._rate_store.pop(key, None)
        result = _run(u.search_unified("johndoe", "username", key))
        names = {s["source"] for s in result["sources"]}
        assert names == {"maigret"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
