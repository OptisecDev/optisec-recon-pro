"""
Tests for Unified OSINT Engine v5.0.
These tests run without real network calls and without requiring external tools.
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from modules.osint.unified_engine import (
    detect_target_type,
    search_unified,
    _check_rate,
    _parse_amass,
    _parse_theharvester,
    _parse_maigret,
    _parse_holehe,
    _rate_store,
    _RATE_MAX,
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
