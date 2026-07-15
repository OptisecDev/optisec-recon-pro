"""
Tests for MITRE ATT&CK Auto-Mapping (deterministic finding -> technique/
tactic mapping + kill-chain attack path generation).

All external HTTP calls are mocked — these tests never hit real APIs (no
GitHub bundle download). Mirrors tests/test_darkweb_intelligence.py's
conventions: plain pytest, async functions driven via asyncio.run().
"""

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aiohttp
import pytest

import modules.osint.mitre_mapping as mm


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def _static_index(monkeypatch):
    """Force _get_attack_index() to use the static fallback instead of
    hitting the network — for tests that exercise the deterministic
    mapping logic, not the live MITRE bundle fetch/cache mechanism
    (see TestAttackIndexCache for that)."""
    monkeypatch.setattr(mm, "_index_memo", None)

    async def _static(force_refresh=False):
        return {"techniques": {}, "tactics": {}, "_source": "static_fallback"}

    monkeypatch.setattr(mm, "_get_attack_index", _static)


# ── 1. Deterministic finding -> ATT&CK mapping (15+ finding types) ──────────

_EXPECTED_MAPPINGS = {
    "port_21_open": (["T1021.004"], ["TA0008"]),
    "port_22_open": (["T1021.004"], ["TA0008"]),
    "port_23_open": (["T1021.004", "T1078"], ["TA0008"]),
    "port_3389_open": (["T1021.001"], ["TA0008"]),
    "port_80_open": (["T1190"], ["TA0001"]),
    "port_443_open": (["T1190"], ["TA0001"]),
    "port_445_open": (["T1021.002"], ["TA0008"]),
    "port_1433_open": (["T1190"], ["TA0001"]),
    "port_3306_open": (["T1190"], ["TA0001"]),
    "port_27017_open": (["T1190"], ["TA0001"]),
    "weak_tls_10": (["T1040"], ["TA0006"]),
    "weak_tls_11": (["T1040"], ["TA0006"]),
    "missing_hsts": (["T1557"], ["TA0006"]),
    "missing_csp": (["T1059.007"], ["TA0002"]),
    "missing_xframe": (["T1185"], ["TA0006"]),
    "missing_xcontent": (["T1059.007"], ["TA0002"]),
    "credential_exposure": (["T1078", "T1110"], ["TA0001"]),
    "email_breach": (["T1589.002"], ["TA0043"]),
    "github_secret_exposed": (["T1552.001"], ["TA0006"]),
    "subdomain_takeover": (["T1584.001"], ["TA0042"]),
    "open_redirect": (["T1566.002"], ["TA0001"]),
    "self_signed_cert": (["T1557"], ["TA0006"]),
    "cert_expired": (["T1557"], ["TA0006"]),
    "weak_cipher": (["T1040"], ["TA0006"]),
    "dns_zone_transfer": (["T1590.002"], ["TA0043"]),
    "s3_bucket_exposed": (["T1530"], ["TA0009"]),
    "api_key_exposed": (["T1552.001"], ["TA0006"]),
    "password_in_url": (["T1552"], ["TA0006"]),
    "directory_listing": (["T1083"], ["TA0007"]),
    "backup_file_exposed": (["T1083"], ["TA0007"]),
    "xss_found": (["T1190"], ["TA0001"]),
    "sqli_found": (["T1190"], ["TA0001"]),
    "ssrf_found": (["T1190"], ["TA0001"]),
    "lfi_found": (["T1190"], ["TA0001"]),
    "graphql_introspection_found": (["T1190"], ["TA0001"]),
}


class TestMapFindingToAttack:
    pytestmark = pytest.mark.usefixtures("_static_index")
    @pytest.mark.parametrize("finding_type", sorted(_EXPECTED_MAPPINGS))
    def test_every_documented_rule_maps_correctly(self, finding_type):
        expected_techniques, expected_tactics = _EXPECTED_MAPPINGS[finding_type]
        result = _run(mm.map_finding_to_attack(finding_type, "example-value"))
        assert result["mapped"] is True
        assert result["error"] is None
        assert [t["id"] for t in result["techniques"]] == expected_techniques
        assert [t["id"] for t in result["tactics"]] == expected_tactics
        # Names must be populated even without live MITRE data (static fallback).
        assert all(t["name"] for t in result["techniques"])
        assert all(t["name"] for t in result["tactics"])

    def test_all_34_rules_covered_by_this_suite(self):
        assert set(_EXPECTED_MAPPINGS) == set(mm._MAPPING_RULES)

    def test_unknown_finding_type_returns_not_mapped(self):
        result = _run(mm.map_finding_to_attack("totally_made_up_finding"))
        assert result["mapped"] is False
        assert result["techniques"] == []
        assert result["tactics"] == []
        assert "no ATT&CK mapping rule" in result["error"]

    def test_preserves_finding_value(self):
        result = _run(mm.map_finding_to_attack("port_22_open", "10.0.0.5:22"))
        assert result["finding_value"] == "10.0.0.5:22"

    def test_data_source_reflects_index_source(self):
        result = _run(mm.map_finding_to_attack("port_22_open"))
        assert result["data_source"] == "static_fallback"

    def test_uses_live_index_when_available(self, monkeypatch):
        async def _live_index(force_refresh=False):
            return {
                "techniques": {"T1021.004": {"id": "T1021.004", "name": "Remote Services: SSH (live)",
                                              "description": "live description", "mitigations": [{"name": "MFA"}]}},
                "tactics": {"TA0008": {"id": "TA0008", "name": "Lateral Movement (live)"}},
                "_source": "live_mitre_data",
            }
        monkeypatch.setattr(mm, "_get_attack_index", _live_index)
        result = _run(mm.map_finding_to_attack("port_22_open"))
        assert result["techniques"][0]["name"] == "Remote Services: SSH (live)"
        assert result["techniques"][0]["mitigations"] == [{"name": "MFA"}]
        assert result["tactics"][0]["name"] == "Lateral Movement (live)"
        assert result["data_source"] == "live_mitre_data"


# ── 2. finding_type_from_entity() normalization ──────────────────────────────

class TestFindingTypeFromEntity:
    def test_direct_type_match(self):
        assert mm.finding_type_from_entity({"type": "missing_hsts"}) == "missing_hsts"

    def test_open_port_known(self):
        assert mm.finding_type_from_entity({"type": "open_port", "port": 3389}) == "port_3389_open"

    def test_open_port_unmapped_returns_none(self):
        assert mm.finding_type_from_entity({"type": "open_port", "port": 9999}) is None

    def test_ssl_issue_self_signed(self):
        entity = {"type": "ssl_issue", "value": "Certificate is self-signed"}
        assert mm.finding_type_from_entity(entity) == "self_signed_cert"

    def test_ssl_issue_expired(self):
        entity = {"type": "ssl_issue", "value": "Certificate has expired"}
        assert mm.finding_type_from_entity(entity) == "cert_expired"

    def test_ssl_issue_weak_tls(self):
        assert mm.finding_type_from_entity({"type": "ssl_issue", "value": "TLSv1.0 is enabled (deprecated)"}) == "weak_tls_10"
        assert mm.finding_type_from_entity({"type": "ssl_issue", "value": "TLSv1.1 is enabled (deprecated)"}) == "weak_tls_11"

    def test_breach_alias(self):
        assert mm.finding_type_from_entity({"type": "breach"}) == "email_breach"

    def test_unrecognized_type_returns_none(self):
        assert mm.finding_type_from_entity({"type": "whois_record"}) is None


class TestFindingTypeFromScanResults:
    pytestmark = pytest.mark.usefixtures("_static_index")

    def test_open_ports_mapped(self):
        scan_results = {"ports": {"open_ports": [
            {"port": 22, "service": "SSH"},
            {"port": 443, "service": "HTTPS"},
        ]}}
        results = mm.finding_type_from_scan_results(scan_results)
        assert {"finding_type": "port_22_open", "finding_value": "SSH (22)"} in results
        assert {"finding_type": "port_443_open", "finding_value": "HTTPS (443)"} in results

    def test_open_port_with_no_rule_is_skipped(self):
        scan_results = {"ports": {"open_ports": [{"port": 9999, "service": "unknown"}]}}
        assert mm.finding_type_from_scan_results(scan_results) == []

    def test_missing_headers_mapped(self):
        scan_results = {"headers": {"missing_headers": {
            "Strict-Transport-Security": {"status": "missing"},
            "Content-Security-Policy": {"status": "missing"},
            "X-Frame-Options": {"status": "missing"},
            "X-Content-Type-Options": {"status": "missing"},
        }}}
        results = mm.finding_type_from_scan_results(scan_results)
        finding_types = {r["finding_type"] for r in results}
        assert finding_types == {"missing_hsts", "missing_csp", "missing_xframe", "missing_xcontent"}

    def test_present_headers_are_not_findings(self):
        scan_results = {"headers": {"missing_headers": {}, "present_headers": {
            "Strict-Transport-Security": {"status": "present", "value": "max-age=31536000"},
        }}}
        assert mm.finding_type_from_scan_results(scan_results) == []

    def test_unrecognized_missing_header_is_skipped(self):
        scan_results = {"headers": {"missing_headers": {"Referrer-Policy": {"status": "missing"}}}}
        assert mm.finding_type_from_scan_results(scan_results) == []

    def test_weak_tls_10_mapped(self):
        scan_results = {"ssl": {"tls_version": "TLSv1", "issuer_name": "DigiCert Inc"}}
        assert mm.finding_type_from_scan_results(scan_results) == [
            {"finding_type": "weak_tls_10", "finding_value": "TLSv1"}
        ]

    def test_weak_tls_11_mapped(self):
        scan_results = {"ssl": {"tls_version": "TLSv1.1", "issuer_name": "DigiCert Inc"}}
        assert mm.finding_type_from_scan_results(scan_results) == [
            {"finding_type": "weak_tls_11", "finding_value": "TLSv1.1"}
        ]

    def test_expired_cert_mapped(self):
        scan_results = {"ssl": {"tls_version": "TLSv1.3", "expired": True, "not_after": "2020-01-01T00:00:00+00:00",
                                 "issuer_name": "DigiCert Inc"}}
        results = mm.finding_type_from_scan_results(scan_results)
        assert {"finding_type": "cert_expired", "finding_value": "2020-01-01T00:00:00+00:00"} in results

    def test_self_signed_cert_mapped_when_no_issuer_name(self):
        scan_results = {"ssl": {"tls_version": "TLSv1.3", "expired": False, "issuer_name": "", "common_name": "example.com"}}
        assert mm.finding_type_from_scan_results(scan_results) == [
            {"finding_type": "self_signed_cert", "finding_value": "example.com"}
        ]

    def test_healthy_ssl_produces_no_findings(self):
        scan_results = {"ssl": {"tls_version": "TLSv1.3", "expired": False, "issuer_name": "DigiCert Inc"}}
        assert mm.finding_type_from_scan_results(scan_results) == []

    def test_ssl_error_dict_produces_no_findings(self):
        # analyze_ssl()'s network/SSL failure shape carries "valid": False
        # but no real cert data — must not be misread as a self-signed cert.
        scan_results = {"ssl": {"domain": "example.com", "error": "Connection refused", "valid": False}}
        assert mm.finding_type_from_scan_results(scan_results) == []

    def test_weak_cipher_is_never_produced(self):
        # ssl_analysis.py records the negotiated cipher name but never
        # classifies it as weak/strong, so this adapter has no signal to
        # act on and must not guess — weak_cipher is intentionally
        # unreachable from here (still reachable via
        # finding_type_from_entity()'s keyword-based ssl_issue matching).
        scan_results = {"ssl": {"tls_version": "TLSv1.3", "expired": False,
                                 "issuer_name": "DigiCert Inc", "cipher": "RC4-MD5"}}
        assert mm.finding_type_from_scan_results(scan_results) == []

    def test_confirmed_vulnerabilities_mapped(self):
        scan_results = {"vulnerabilities": [
            {"type": "XSS", "verdict": "CONFIRMED", "url": "https://example.com/search?q=x"},
            {"type": "SQL Injection", "verdict": "CONFIRMED", "url": "https://example.com/item?id=1"},
            {"type": "SQL Injection (Blind)", "verdict": "CONFIRMED", "url": "https://example.com/item?id=2"},
            {"type": "SSRF", "verdict": "CONFIRMED", "url": "https://example.com/fetch?url=x"},
            {"type": "LFI", "verdict": "CONFIRMED", "url": "https://example.com/view?file=x"},
            {"type": "Open Redirect", "verdict": "CONFIRMED", "url": "https://example.com/go?to=x"},
        ]}
        results = mm.finding_type_from_scan_results(scan_results)
        finding_types = [r["finding_type"] for r in results]
        assert finding_types == ["xss_found", "sqli_found", "sqli_found", "ssrf_found", "lfi_found", "open_redirect"]

    def test_non_confirmed_vulnerability_is_skipped(self):
        scan_results = {"vulnerabilities": [
            {"type": "XSS", "verdict": "WAF_BLOCKED", "url": "https://example.com/search?q=x"},
        ]}
        assert mm.finding_type_from_scan_results(scan_results) == []

    def test_unrecognized_vuln_type_is_skipped(self):
        scan_results = {"vulnerabilities": [{"type": "Something Else", "verdict": "CONFIRMED"}]}
        assert mm.finding_type_from_scan_results(scan_results) == []

    def test_empty_scan_results(self):
        assert mm.finding_type_from_scan_results({}) == []

    def test_combined_categories_all_flow_through(self):
        scan_results = {
            "ports": {"open_ports": [{"port": 3389, "service": "RDP"}]},
            "headers": {"missing_headers": {"Content-Security-Policy": {"status": "missing"}}},
            "ssl": {"tls_version": "TLSv1", "expired": False, "issuer_name": "Let's Encrypt"},
            "vulnerabilities": [{"type": "SSRF", "verdict": "CONFIRMED", "url": "https://example.com/fetch"}],
        }
        finding_types = {r["finding_type"] for r in mm.finding_type_from_scan_results(scan_results)}
        assert finding_types == {"port_3389_open", "missing_csp", "weak_tls_10", "ssrf_found"}

    def test_results_are_mappable_end_to_end(self):
        scan_results = {"vulnerabilities": [{"type": "XSS", "verdict": "CONFIRMED", "url": "https://example.com/x"}]}
        findings = mm.finding_type_from_scan_results(scan_results)
        result = _run(mm.map_finding_to_attack(findings[0]["finding_type"], findings[0]["finding_value"]))
        assert result["mapped"] is True
        assert [t["id"] for t in result["techniques"]] == ["T1190"]
        assert [t["id"] for t in result["tactics"]] == ["TA0001"]


class TestMapFindingsToAttack:
    pytestmark = pytest.mark.usefixtures("_static_index")
    def test_skips_unrecognized_and_maps_rest(self):
        entities = [
            {"type": "open_port", "port": 22, "value": "1.2.3.4:22"},
            {"type": "whois_record", "value": "irrelevant"},
            {"type": "missing_hsts", "value": "https://example.com"},
        ]
        results = _run(mm.map_findings_to_attack(entities))
        assert len(results) == 2
        mapped_types = {r["finding_type"] for r in results}
        assert mapped_types == {"port_22_open", "missing_hsts"}

    def test_empty_input(self):
        assert _run(mm.map_findings_to_attack([])) == []


# ── 3. Attack path generation — kill chain ordering ──────────────────────────

class TestGenerateAttackPath:
    pytestmark = pytest.mark.usefixtures("_static_index")
    def test_orders_by_full_kill_chain_regardless_of_input_order(self):
        # Deliberately out of kill-chain order: Lateral Movement, then
        # Initial Access, then Credential Access, then Reconnaissance.
        findings = [
            {"finding_type": "port_22_open"},       # TA0008 Lateral Movement
            {"finding_type": "port_80_open"},        # TA0001 Initial Access
            {"finding_type": "weak_cipher"},          # TA0006 Credential Access
            {"finding_type": "dns_zone_transfer"},    # TA0043 Reconnaissance
        ]
        result = _run(mm.generate_attack_path(findings))
        tactic_ids = [step["tactic_id"] for step in result["attack_path"]]
        assert tactic_ids == ["TA0043", "TA0001", "TA0006", "TA0008"]
        # Step numbers increase monotonically along the path.
        assert [step["step"] for step in result["attack_path"]] == [1, 2, 3, 4]

    def test_kill_chain_order_matches_official_14_stage_sequence(self):
        assert mm._KILL_CHAIN_ORDER == [
            "TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
            "TA0006", "TA0007", "TA0008", "TA0009", "TA0011", "TA0010", "TA0040",
        ]

    def test_unmapped_findings_are_skipped_not_erroring(self):
        findings = [{"finding_type": "not_a_real_rule"}, {"finding_type": "port_22_open"}]
        result = _run(mm.generate_attack_path(findings))
        assert result["mapped_findings"] == 1
        assert result["total_findings_analyzed"] == 2
        assert result["path_length"] == 1

    def test_accepts_raw_unified_engine_entities(self):
        findings = [{"type": "open_port", "port": 445, "value": "10.0.0.1:445"}]
        result = _run(mm.generate_attack_path(findings))
        assert result["mapped_findings"] == 1
        assert result["attack_path"][0]["tactic_id"] == "TA0008"

    def test_empty_findings_returns_empty_path(self):
        result = _run(mm.generate_attack_path([]))
        assert result["attack_path"] == []
        assert result["path_length"] == 0
        assert result["mapped_findings"] == 0

    def test_deduplicates_techniques_within_a_tactic(self):
        # port_21_open and port_22_open both map to T1021.004/TA0008 —
        # the technique should only appear once in that tactic's step.
        findings = [{"finding_type": "port_21_open"}, {"finding_type": "port_22_open"}]
        result = _run(mm.generate_attack_path(findings))
        assert len(result["attack_path"]) == 1
        technique_ids = [t["id"] for t in result["attack_path"][0]["techniques"]]
        assert technique_ids == ["T1021.004"]

    def test_likelihood_is_bounded_between_zero_and_one(self):
        findings = [{"finding_type": ft} for ft in mm._MAPPING_RULES]
        result = _run(mm.generate_attack_path(findings))
        for step in result["attack_path"]:
            assert 0.0 <= step["likelihood"] <= 1.0


# ── 4. MITRE bundle fetch + cache mechanism ──────────────────────────────────

_FAKE_BUNDLE = {
    "objects": [
        {
            "type": "x-mitre-tactic", "x_mitre_shortname": "lateral-movement", "name": "Lateral Movement",
            "external_references": [{"source_name": "mitre-attack", "external_id": "TA0008"}],
        },
        {
            "type": "attack-pattern", "id": "attack-pattern--ssh", "name": "SSH",
            "description": "Adversaries may use SSH.",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "lateral-movement"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1021.004"}],
        },
        {
            "type": "course-of-action", "id": "course-of-action--mfa", "name": "Multi-factor Authentication",
            "description": "Use MFA.",
        },
        {
            "type": "relationship", "relationship_type": "mitigates",
            "source_ref": "course-of-action--mfa", "target_ref": "attack-pattern--ssh",
        },
    ]
}


class _FakeResponse:
    def __init__(self, status=200, json_data=None):
        self.status = status
        self._json_data = json_data or {}

    async def json(self, content_type=None):
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
        return self._responder(url, kwargs)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class TestAttackIndexCache:
    @pytest.fixture(autouse=True)
    def _isolated_cache(self, tmp_path, monkeypatch):
        cache_path = tmp_path / "mitre_cache.json"
        monkeypatch.setattr(mm, "_MITRE_CACHE_PATH", cache_path)
        monkeypatch.setattr(mm, "_index_memo", None)
        yield cache_path

    def test_build_index_extracts_techniques_tactics_mitigations(self):
        index = mm._build_index(_FAKE_BUNDLE)
        assert "T1021.004" in index["techniques"]
        technique = index["techniques"]["T1021.004"]
        assert technique["name"] == "SSH"
        assert technique["tactics"][0]["id"] == "TA0008"
        assert technique["mitigations"][0]["name"] == "Multi-factor Authentication"
        assert index["tactics"]["TA0008"]["name"] == "Lateral Movement"

    def test_fetches_and_writes_cache_file(self, monkeypatch, _isolated_cache):
        monkeypatch.setattr(
            aiohttp, "ClientSession",
            lambda *a, **kw: _FakeSession(lambda url, kwargs: _FakeResponse(200, _FAKE_BUNDLE)),
        )
        index = _run(mm._get_attack_index())
        assert index["_source"] == "live_mitre_data"
        assert "T1021.004" in index["techniques"]
        assert _isolated_cache.exists()

    def test_second_call_uses_disk_cache_without_network(self, monkeypatch, _isolated_cache):
        calls = {"n": 0}

        def _session_factory(*a, **kw):
            calls["n"] += 1
            return _FakeSession(lambda url, kwargs: _FakeResponse(200, _FAKE_BUNDLE))

        monkeypatch.setattr(aiohttp, "ClientSession", _session_factory)
        _run(mm._get_attack_index())
        assert calls["n"] == 1

        monkeypatch.setattr(mm, "_index_memo", None)  # force re-read from disk, not process memo
        index = _run(mm._get_attack_index())
        assert index["_source"] == "cached_mitre_data"
        assert calls["n"] == 1  # no second network call

    def test_expired_cache_triggers_refetch(self, monkeypatch, _isolated_cache):
        _isolated_cache.write_text(json.dumps({"cached_at": 0, "index": {"techniques": {}, "tactics": {}}}))
        monkeypatch.setattr(
            aiohttp, "ClientSession",
            lambda *a, **kw: _FakeSession(lambda url, kwargs: _FakeResponse(200, _FAKE_BUNDLE)),
        )
        index = _run(mm._get_attack_index())
        assert index["_source"] == "live_mitre_data"

    def test_unreachable_bundle_falls_back_to_static(self, monkeypatch, _isolated_cache):
        def _raise(*a, **kw):
            raise aiohttp.ClientConnectionError("network down")
        monkeypatch.setattr(aiohttp, "ClientSession", _raise)
        index = _run(mm._get_attack_index())
        assert index["_source"] == "static_fallback"
        assert index["techniques"] == {}

    def test_process_memo_avoids_disk_read_on_repeat_calls(self, monkeypatch, _isolated_cache):
        monkeypatch.setattr(
            aiohttp, "ClientSession",
            lambda *a, **kw: _FakeSession(lambda url, kwargs: _FakeResponse(200, _FAKE_BUNDLE)),
        )
        first = _run(mm._get_attack_index())
        # Corrupt the cache file — if the memo weren't used, this would raise/fallback.
        _isolated_cache.write_text("not json")
        second = _run(mm._get_attack_index())
        assert first is second


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
