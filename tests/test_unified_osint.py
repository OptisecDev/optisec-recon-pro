"""
Tests for Unified OSINT Engine v5.0.
These tests run without real network calls and without requiring external tools.
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from datetime import datetime, timedelta, timezone

import pytest
from modules.osint.unified_engine import (
    detect_target_type,
    search_unified,
    _check_rate,
    _parse_amass,
    _parse_theharvester,
    _parse_maigret,
    _parse_holehe,
    _parse_crtsh_json,
    _parse_wayback_cdx,
    get_sources_status,
    _rate_store,
    _RATE_MAX,
)
from modules.osint.confidence_engine import (
    calculate_confidence,
    classify_severity,
    SOURCE_RELIABILITY,
)
from modules.osint.correlation_engine import (
    deduplicate_and_merge,
    build_entity_graph,
)


# ── Target-type detection ──────────────────────────────────────────────────────

class TestDetectTargetType:
    def test_domain_simple(self):
        assert detect_target_type("example.com") == "domain"

    def test_domain_subdomain(self):
        assert detect_target_type("sub.example.co.uk") == "domain"

    def test_domain_with_dashes(self):
        assert detect_target_type("my-site.example.org") == "domain"

    def test_email(self):
        assert detect_target_type("user@example.com") == "email"

    def test_email_subdomain(self):
        assert detect_target_type("user@mail.example.com") == "email"

    def test_ip_v4(self):
        assert detect_target_type("192.168.1.1") == "ip"

    def test_ip_public(self):
        assert detect_target_type("8.8.8.8") == "ip"

    def test_username_simple(self):
        assert detect_target_type("johndoe") == "username"

    def test_username_with_underscore(self):
        assert detect_target_type("john_doe99") == "username"

    def test_username_with_numbers(self):
        assert detect_target_type("h4x0r") == "username"


# ── Rate limiter ───────────────────────────────────────────────────────────────

class TestRateLimiter:
    def test_allows_up_to_max(self):
        key = "__test_rate_allows__"
        _rate_store.pop(key, None)
        for _ in range(_RATE_MAX):
            assert _check_rate(key) is True

    def test_blocks_after_max(self):
        key = "__test_rate_blocks__"
        _rate_store.pop(key, None)
        for _ in range(_RATE_MAX):
            _check_rate(key)
        assert _check_rate(key) is False

    def test_independent_keys(self):
        key_a = "__test_rate_a__"
        key_b = "__test_rate_b__"
        _rate_store.pop(key_a, None)
        _rate_store.pop(key_b, None)
        for _ in range(_RATE_MAX):
            _check_rate(key_a)
        # key_a is exhausted, key_b should still be fine
        assert _check_rate(key_b) is True


# ── Output parsers ─────────────────────────────────────────────────────────────

class TestParsers:
    def test_parse_amass_basic(self):
        out = "www.example.com\napi.example.com\nwww.example.com\n"
        results = _parse_amass(out)
        values = [r["value"] for r in results]
        assert "www.example.com" in values
        assert "api.example.com" in values
        # deduplication
        assert values.count("www.example.com") == 1

    def test_parse_amass_empty(self):
        assert _parse_amass("") == []

    def test_parse_theharvester_emails(self):
        out = (
            "[*] Emails found:\n"
            "alice@example.com\n"
            "bob@example.com\n"
            "[*] Hosts found:\n"
            "mail.example.com\n"
        )
        results = _parse_theharvester(out)
        emails = [r["value"] for r in results if r["type"] == "email"]
        hosts  = [r["value"] for r in results if r["type"] == "host"]
        assert "alice@example.com" in emails
        assert "bob@example.com" in emails
        assert "mail.example.com" in hosts

    def test_parse_theharvester_empty(self):
        assert _parse_theharvester("") == []

    def test_parse_maigret_json(self):
        import json
        data = {
            "GitHub": {"status": {"id": "CLAIMED"}, "url_user": "https://github.com/user"},
            "Twitter": {"status": {"id": "NOT_FOUND"}, "url_user": ""},
        }
        results = _parse_maigret(json.dumps(data))
        platforms = [r["platform"] for r in results]
        assert "GitHub" in platforms
        assert "Twitter" not in platforms

    def test_parse_maigret_text_fallback(self):
        out = "[+] GitHub: https://github.com/johndoe\n"
        results = _parse_maigret(out)
        assert len(results) >= 1
        assert results[0]["status"] == "found"

    def test_parse_maigret_empty(self):
        assert _parse_maigret("") == []

    def test_parse_holehe_json(self):
        import json
        data = [
            {"name": "Twitter", "exists": True, "domain": "twitter.com"},
            {"name": "GitHub", "exists": False, "domain": "github.com"},
        ]
        results = _parse_holehe(json.dumps(data))
        platforms = [r["platform"] for r in results]
        assert "Twitter" in platforms
        assert "GitHub" not in platforms

    def test_parse_holehe_text_fallback(self):
        out = "[+] Instagram: account exists\n[-] Twitter: not found\n"
        results = _parse_holehe(out)
        assert len(results) >= 1
        assert results[0]["status"] == "registered"

    def test_parse_holehe_empty(self):
        assert _parse_holehe("") == []


# ── Unified search (no external tools required) ───────────────────────────────

class TestSearchUnified:
    def _run(self, coro):
        return asyncio.run(coro)

    def test_domain_returns_correct_structure(self):
        result = self._run(
            search_unified("example.com", "domain", "__test_domain__")
        )
        assert result["target"] == "example.com"
        assert result["target_type"] == "domain"
        assert "sources" in result
        assert isinstance(result["sources"], list)
        assert "total_results" in result
        assert "elapsed_seconds" in result
        # Should have tried amass + theharvester
        source_names = [s["source"] for s in result["sources"]]
        assert "amass" in source_names
        assert "theHarvester" in source_names

    def test_email_returns_correct_sources(self):
        result = self._run(
            search_unified("test@example.com", "email", "__test_email__")
        )
        assert result["target_type"] == "email"
        source_names = [s["source"] for s in result["sources"]]
        assert "holehe" in source_names
        assert "theHarvester" in source_names

    def test_username_returns_correct_sources(self):
        result = self._run(
            search_unified("johndoe", "username", "__test_user__")
        )
        assert result["target_type"] == "username"
        source_names = [s["source"] for s in result["sources"]]
        assert "maigret" in source_names

    def test_ip_returns_correct_sources(self):
        result = self._run(
            search_unified("8.8.8.8", "ip", "__test_ip__")
        )
        assert result["target_type"] == "ip"
        source_names = [s["source"] for s in result["sources"]]
        assert "theHarvester" in source_names

    def test_auto_detects_domain(self):
        result = self._run(
            search_unified("google.com", "auto", "__test_auto_domain__")
        )
        assert result["target_type"] == "domain"

    def test_auto_detects_email(self):
        result = self._run(
            search_unified("user@test.com", "auto", "__test_auto_email__")
        )
        assert result["target_type"] == "email"

    def test_unavailable_tools_return_graceful_error(self):
        result = self._run(
            search_unified("example.com", "domain", "__test_unavail__")
        )
        for source in result["sources"]:
            # Should always have a results list, even if empty
            assert "results" in source
            assert isinstance(source["results"], list)
            # Available=False is acceptable when tool not installed
            if not source.get("available", True):
                assert "error" in source

    def test_rate_limited_response(self):
        key = "__test_unified_rate__"
        _rate_store.pop(key, None)
        for _ in range(_RATE_MAX):
            _check_rate(key)
        result = self._run(search_unified("example.com", "domain", key))
        assert result.get("error") == "rate_limited"
        assert "message" in result


# ── New passive-source parsers (crt.sh / Wayback) ──────────────────────────────

class TestParseCrtsh:
    def test_extracts_matching_subdomains(self):
        sample = json.dumps([
            {
                "name_value": "api.example.com\n*.dev.example.com",
                "issuer_name": "C=US, O=Let's Encrypt",
                "not_before": "2024-01-01T00:00:00",
            },
            {"name_value": "unrelated-domain.org", "issuer_name": "X", "not_before": ""},
        ])
        results = _parse_crtsh_json(sample, "example.com")
        values = [r["value"] for r in results]
        assert "api.example.com" in values
        assert "dev.example.com" in values  # wildcard "*." stripped
        assert "unrelated-domain.org" not in values  # filtered: not a subdomain of target

    def test_deduplicates(self):
        sample = json.dumps([
            {"name_value": "api.example.com", "issuer_name": "A", "not_before": ""},
            {"name_value": "api.example.com", "issuer_name": "B", "not_before": ""},
        ])
        results = _parse_crtsh_json(sample, "example.com")
        assert len(results) == 1

    def test_malformed_json_returns_empty(self):
        assert _parse_crtsh_json("not json", "example.com") == []

    def test_empty_input(self):
        assert _parse_crtsh_json("[]", "example.com") == []


class TestParseWayback:
    def test_extracts_distinct_hosts(self):
        sample = json.dumps([
            ["original"],
            ["http://api.example.com/path"],
            ["https://www.example.com/"],
            ["http://api.example.com/other-page"],  # duplicate host
        ])
        results = _parse_wayback_cdx(sample)
        hosts = [r["value"] for r in results]
        assert hosts.count("api.example.com") == 1
        assert "www.example.com" in hosts

    def test_header_only_returns_empty(self):
        assert _parse_wayback_cdx(json.dumps([["original"]])) == []

    def test_malformed_json_returns_empty(self):
        assert _parse_wayback_cdx("not json") == []

    def test_empty_input(self):
        assert _parse_wayback_cdx("[]") == []


# ── Source status ──────────────────────────────────────────────────────────────

class TestSourcesStatus:
    def test_returns_all_sources(self):
        statuses = get_sources_status()
        names = {s["source"] for s in statuses}
        assert names == {
            "amass", "theharvester", "maigret", "holehe",
            "crtsh", "wayback", "dns_full", "whois", "network_intel", "darkweb_intel",
        }

    def test_direct_api_sources_always_available(self):
        statuses = {s["source"]: s for s in get_sources_status()}
        for name in ("crtsh", "wayback", "dns_full", "whois"):
            assert statuses[name]["available"] is True
            assert statuses[name]["requires_api_key"] is False

    def test_entries_have_required_keys(self):
        for status in get_sources_status():
            assert {"source", "available", "requires_api_key", "last_used"} <= status.keys()


# ── Confidence Engine ────────────────────────────────────────────────────────────

class TestCalculateConfidence:
    def test_single_source_uses_its_reliability(self):
        finding = {"source": "crtsh", "value": "api.example.com"}
        score = calculate_confidence(finding, [])
        assert score == SOURCE_RELIABILITY["crtsh"]

    def test_unknown_source_uses_default_reliability(self):
        finding = {"source": "totally-new-tool", "value": "x"}
        score = calculate_confidence(finding, [])
        assert score == 50

    def test_corroboration_increases_score(self):
        single = calculate_confidence({"sources": ["wayback"], "value": "x"}, [])
        double = calculate_confidence({"sources": ["wayback", "maigret"], "value": "x"}, [])
        assert double > single
        assert double == single + 15

    def test_score_capped_at_100(self):
        finding = {"sources": ["crtsh", "dns_full", "whois", "amass"], "value": "x"}
        assert calculate_confidence(finding, []) == 100

    def test_no_sources_scores_zero(self):
        assert calculate_confidence({"value": "x"}, []) == 0

    def test_falls_back_to_scanning_all_results(self):
        finding = {"value": "shared.example.com"}
        all_results = [
            {"source": "wayback", "results": [{"type": "subdomain", "value": "shared.example.com"}]},
            {"source": "maigret", "results": [{"type": "subdomain", "value": "shared.example.com"}]},
        ]
        score = calculate_confidence(finding, all_results)
        expected_base = max(SOURCE_RELIABILITY["wayback"], SOURCE_RELIABILITY["maigret"])
        assert score == expected_base + 15

    def test_recent_timestamp_gives_freshness_bonus(self):
        recent = {"source": "wayback", "value": "x", "timestamp": datetime.now(timezone.utc).isoformat()}
        baseline = calculate_confidence({"source": "wayback", "value": "x"}, [])
        boosted = calculate_confidence(recent, [])
        assert boosted == baseline + 5

    def test_stale_timestamp_gives_penalty(self):
        old_date = (datetime.now(timezone.utc) - timedelta(days=900)).isoformat()
        stale = {"source": "wayback", "value": "x", "not_before": old_date}
        baseline = calculate_confidence({"source": "wayback", "value": "x"}, [])
        penalized = calculate_confidence(stale, [])
        assert penalized == baseline - 10


class TestClassifySeverity:
    def test_subdomain_default_is_low(self):
        assert classify_severity({"type": "subdomain", "value": "api.example.com"}) == "low"

    def test_subdomain_without_tls_is_high(self):
        finding = {"type": "subdomain", "value": "api.example.com", "tls": False}
        assert classify_severity(finding) == "high"

    def test_dmarc_missing_is_medium(self):
        assert classify_severity({"type": "dmarc_status", "value": "missing"}) == "medium"

    def test_spf_missing_is_medium(self):
        assert classify_severity({"type": "spf_status", "value": "missing"}) == "medium"

    def test_whois_expiring_soon_is_critical(self):
        soon = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S+00:00")
        finding = {"type": "whois_record", "expiration_date": soon}
        assert classify_severity(finding) == "critical"

    def test_whois_freshly_registered_is_medium(self):
        recent = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d %H:%M:%S+00:00")
        far_expiry = (datetime.now(timezone.utc) + timedelta(days=900)).strftime("%Y-%m-%d %H:%M:%S+00:00")
        finding = {"type": "whois_record", "creation_date": recent, "expiration_date": far_expiry}
        assert classify_severity(finding) == "medium"

    def test_whois_normal_is_info(self):
        old = (datetime.now(timezone.utc) - timedelta(days=3000)).strftime("%Y-%m-%d %H:%M:%S+00:00")
        far_expiry = (datetime.now(timezone.utc) + timedelta(days=900)).strftime("%Y-%m-%d %H:%M:%S+00:00")
        finding = {"type": "whois_record", "creation_date": old, "expiration_date": far_expiry}
        assert classify_severity(finding) == "info"

    def test_email_is_medium(self):
        assert classify_severity({"type": "email", "value": "a@example.com"}) == "medium"

    def test_account_is_medium(self):
        assert classify_severity({"type": "account", "value": "x"}) == "medium"

    def test_profile_is_low(self):
        assert classify_severity({"type": "profile", "value": "x"}) == "low"

    def test_dns_record_is_info(self):
        assert classify_severity({"type": "dns_record", "value": "1.2.3.4"}) == "info"

    def test_unknown_type_is_info(self):
        assert classify_severity({"type": "something-new"}) == "info"


# ── Correlation & Deduplication Engine ──────────────────────────────────────────

class TestDeduplicateAndMerge:
    def test_merges_same_entity_from_two_sources(self):
        results = [
            {"source": "crtsh", "results": [{"type": "subdomain", "value": "api.example.com"}]},
            {"source": "dns_full", "results": [{"type": "subdomain", "value": "api.example.com"}]},
        ]
        merged = deduplicate_and_merge(results)
        assert len(merged) == 1
        entry = merged[0]
        assert set(entry["sources"]) == {"crtsh", "dns_full"}
        assert entry["occurrences"] == 2

    def test_distinct_entities_stay_separate(self):
        results = [
            {"source": "crtsh", "results": [{"type": "subdomain", "value": "a.example.com"}]},
            {"source": "crtsh", "results": [{"type": "subdomain", "value": "b.example.com"}]},
        ]
        merged = deduplicate_and_merge(results)
        assert len(merged) == 2

    def test_backfills_missing_fields_from_richer_source(self):
        results = [
            {"source": "dns_full", "results": [{"type": "subdomain", "value": "api.example.com"}]},
            {"source": "crtsh", "results": [{
                "type": "subdomain", "value": "api.example.com", "issuer": "Let's Encrypt",
            }]},
        ]
        merged = deduplicate_and_merge(results)
        assert merged[0]["issuer"] == "Let's Encrypt"

    def test_does_not_overwrite_explicit_false(self):
        results = [
            {"source": "amass", "results": [{"type": "subdomain", "value": "api.example.com", "tls": False}]},
            {"source": "crtsh", "results": [{"type": "subdomain", "value": "api.example.com"}]},
        ]
        merged = deduplicate_and_merge(results)
        assert merged[0]["tls"] is False

    def test_empty_input(self):
        assert deduplicate_and_merge([]) == []

    def test_skips_findings_without_value(self):
        results = [{"source": "x", "results": [{"type": "subdomain"}]}]
        assert deduplicate_and_merge(results) == []


class TestBuildEntityGraph:
    def test_email_related_to_its_domain(self):
        results = [
            {"source": "whois", "results": [{"type": "whois_record", "value": "example.com"}]},
            {"source": "theharvester", "results": [{"type": "email", "value": "admin@example.com"}]},
        ]
        graph = build_entity_graph(results)
        assert graph["admin@example.com"]["related_to"] == "example.com"

    def test_subdomain_related_to_apex_when_present(self):
        results = [
            {"source": "whois", "results": [{"type": "whois_record", "value": "example.com"}]},
            {"source": "crtsh", "results": [{"type": "subdomain", "value": "api.example.com"}]},
        ]
        graph = build_entity_graph(results)
        assert graph["api.example.com"]["related_to"] == "example.com"

    def test_subdomain_unrelated_when_apex_absent(self):
        results = [
            {"source": "crtsh", "results": [{"type": "subdomain", "value": "api.example.com"}]},
        ]
        graph = build_entity_graph(results)
        assert graph["api.example.com"]["related_to"] is None

    def test_graph_keyed_by_lowercased_value(self):
        results = [
            {"source": "crtsh", "results": [{"type": "subdomain", "value": "API.Example.com"}]},
        ]
        graph = build_entity_graph(results)
        assert "api.example.com" in graph


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
