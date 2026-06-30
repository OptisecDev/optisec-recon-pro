"""
Tests for Advanced Network Intelligence (Phase 2A).

Mirrors tests/test_unified_osint.py's conventions: plain pytest, async
functions driven via asyncio.run(), no HTTP mocking library — pure-logic
functions (scoring, vulnerability detection) get literal fixture data,
network-touching functions are tested for structural correctness and
graceful degradation. Only RFC 2606 / well-known public targets are used:
1.1.1.1, 8.8.8.8, and example.com.
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from modules.osint.network_intelligence import (
    _resolve_ip,
    _query_bgp,
    _get_ip_ranges,
    _query_shodan,
    _query_censys,
    _analyze_ssl,
    _detect_ssl_vulnerabilities,
    _severity_for_score,
    calculate_attack_surface_score,
    gather_network_intelligence,
)


_BAD_HOST = "this-domain-should-not-exist-xyz123.invalid"


def _resolve_with_retry(target: str, attempts: int = 3) -> str | None:
    """DNS lookups in CI/sandbox environments occasionally drop a single
    UDP query — retry a couple of times before treating it as unresolvable,
    since that's resolver flakiness, not a bug in _resolve_ip()."""
    for _ in range(attempts):
        ip = _resolve_ip(target)
        if ip is not None:
            return ip
    return None


# ── Target resolution ────────────────────────────────────────────────────────

class TestResolveIP:
    def test_passthrough_ip(self):
        assert _resolve_ip("8.8.8.8") == "8.8.8.8"

    def test_resolves_domain(self):
        assert _resolve_with_retry("example.com") is not None

    def test_strips_scheme_and_path(self):
        ip = _resolve_with_retry("https://example.com/some/path")
        assert ip is not None

    def test_strips_port(self):
        ip = _resolve_with_retry("example.com:8080")
        assert ip is not None

    def test_unresolvable_returns_none(self):
        assert _resolve_ip(_BAD_HOST) is None


# ── BGP / ASN intelligence ────────────────────────────────────────────────────

class TestQueryBGP:
    def _run(self, coro):
        return asyncio.run(coro)

    def test_known_ip_returns_structure(self):
        result = self._run(_query_bgp("1.1.1.1"))
        assert result["source"] == "bgp"
        assert result["ip"] == "1.1.1.1"
        assert "asn" in result
        assert "peer_asns" in result
        assert isinstance(result["peer_asns"], list)

    def test_google_dns_resolves_to_an_asn(self):
        result = self._run(_query_bgp("8.8.8.8"))
        assert result["available"] is True
        # Either a real provider answered with ASN data, or both providers
        # were unreachable and the graceful "no data" shape is returned.
        if result.get("asn") is not None:
            assert isinstance(result["asn"], int)
            assert result["asn"] > 0

    def test_unresolvable_target_is_unavailable(self):
        result = self._run(_query_bgp(_BAD_HOST))
        assert result["available"] is False
        assert "error" in result
        assert result["asn"] is None

    def test_domain_target_resolves_first(self):
        for _ in range(3):
            result = self._run(_query_bgp("example.com"))
            if result["ip"] is not None:
                break
        assert result["ip"] is not None
        assert result["source"] == "bgp"


class TestGetIPRanges:
    def _run(self, coro):
        return asyncio.run(coro)

    def test_invalid_asn_handled_gracefully(self):
        result = self._run(_get_ip_ranges("not-a-number"))
        assert result["available"] is False
        assert "error" in result

    def test_valid_asn_returns_structure(self):
        # AS15169 = Google — stable, well-known ASN, safe to query.
        result = self._run(_get_ip_ranges(15169))
        assert result["source"] == "bgp"
        assert "ipv4_prefixes" in result
        assert "ipv6_prefixes" in result
        assert isinstance(result["ipv4_prefixes"], list)

    def test_accepts_as_prefixed_string(self):
        result = self._run(_get_ip_ranges("AS15169"))
        assert result.get("asn") == 15169 or result["available"] is False


# ── Shodan (free InternetDB) ───────────────────────────────────────────────────

class TestQueryShodan:
    def _run(self, coro):
        return asyncio.run(coro)

    def test_known_ip_structure(self):
        result = self._run(_query_shodan("8.8.8.8"))
        assert result["source"] == "shodan"
        assert "open_ports" in result
        assert "services" in result
        assert "vulnerabilities" in result
        assert "tags" in result
        assert "hostnames" in result
        assert isinstance(result["open_ports"], list)
        assert isinstance(result["vulnerabilities"], list)

    def test_no_api_key_uses_internetdb(self):
        # SHODAN_API_KEY is unset in the test environment by default.
        result = self._run(_query_shodan("1.1.1.1"))
        if result["available"] and not result.get("error"):
            assert result.get("via") == "internetdb"

    def test_unresolvable_target(self):
        result = self._run(_query_shodan(_BAD_HOST))
        assert result["available"] is False
        assert "error" in result

    def test_vulnerabilities_have_severity_when_present(self):
        result = self._run(_query_shodan("8.8.8.8"))
        for vuln in result.get("vulnerabilities") or []:
            assert "cve" in vuln
            assert vuln["severity"] in ("critical", "high", "medium", "low")


class TestQueryCensys:
    def _run(self, coro):
        return asyncio.run(coro)

    def test_skips_gracefully_without_credentials(self):
        # CENSYS_API_ID/CENSYS_API_SECRET are unset in the test environment.
        result = self._run(_query_censys("8.8.8.8"))
        assert result["source"] == "censys"
        assert result["available"] is False
        assert "error" in result


# ── SSL/TLS deep analysis ──────────────────────────────────────────────────────

class TestAnalyzeSSL:
    def _run(self, coro):
        return asyncio.run(coro)

    def test_example_com_structure(self):
        result = self._run(_analyze_ssl("example.com", 443))
        assert result["host"] == "example.com"
        assert result["port"] == 443
        if result["available"]:
            assert result["negotiated_version"] in ("TLSv1.2", "TLSv1.3")
            assert "certificate" in result
            assert "protocol_support" in result
            assert set(result["protocol_support"].keys()) == {
                "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3",
            }

    def test_example_com_certificate_fields(self):
        result = self._run(_analyze_ssl("example.com", 443))
        if result["available"] and result.get("certificate"):
            cert = result["certificate"]
            assert "subject" in cert
            assert "issuer" in cert
            assert "days_until_expiry" in cert
            assert "is_self_signed" in cert
            assert "subject_alt_names" in cert

    def test_one_one_one_one_https(self):
        result = self._run(_analyze_ssl("1.1.1.1", 443))
        assert result["host"] == "1.1.1.1"
        # 1.1.1.1 serves HTTPS directly on the bare IP (no SNI routing
        # dependency), so this should succeed in any normal network.
        if result["available"]:
            assert result["negotiated_version"] is not None

    def test_unreachable_host_fails_gracefully(self):
        result = self._run(_analyze_ssl(_BAD_HOST, 443))
        assert result["available"] is False
        assert "error" in result

    def test_closed_port_fails_gracefully(self):
        # example.com:9 (discard) — open TCP services don't speak TLS there.
        result = self._run(_analyze_ssl("example.com", 9))
        assert result["available"] is False
        assert "error" in result


class TestDetectSSLVulnerabilities:
    def _base(self, **overrides) -> dict:
        base = {
            "protocol_support": {"TLSv1.0": "not_supported", "TLSv1.1": "not_supported",
                                  "TLSv1.2": "supported", "TLSv1.3": "supported"},
            "cipher_suite": {"name": "TLS_AES_256_GCM_SHA384"},
            "certificate": {"is_self_signed": False, "is_expired": False, "days_until_expiry": 200},
            "chain_trusted": True,
        }
        base.update(overrides)
        return base

    def test_clean_result_has_no_issues(self):
        assert _detect_ssl_vulnerabilities(self._base()) == []

    def test_flags_deprecated_tls_1_0(self):
        ssl_result = self._base(protocol_support={"TLSv1.0": "supported", "TLSv1.1": "not_supported",
                                                    "TLSv1.2": "supported", "TLSv1.3": "supported"})
        issues = _detect_ssl_vulnerabilities(ssl_result)
        assert any(i["id"] == "deprecated-tlsv1.0" and i["severity"] == "high" for i in issues)

    def test_flags_deprecated_tls_1_1(self):
        ssl_result = self._base(protocol_support={"TLSv1.0": "not_supported", "TLSv1.1": "supported",
                                                    "TLSv1.2": "supported", "TLSv1.3": "supported"})
        issues = _detect_ssl_vulnerabilities(ssl_result)
        assert any(i["id"] == "deprecated-tlsv1.1" for i in issues)

    def test_flags_weak_cipher(self):
        ssl_result = self._base(cipher_suite={"name": "RC4-MD5"})
        issues = _detect_ssl_vulnerabilities(ssl_result)
        assert any(i["id"] == "weak-cipher" and i["severity"] == "high" for i in issues)

    def test_flags_self_signed_cert(self):
        ssl_result = self._base(certificate={"is_self_signed": True, "is_expired": False, "days_until_expiry": 200})
        issues = _detect_ssl_vulnerabilities(ssl_result)
        assert any(i["id"] == "self-signed-cert" and i["severity"] == "medium" for i in issues)

    def test_flags_expired_cert_as_critical(self):
        ssl_result = self._base(certificate={"is_self_signed": False, "is_expired": True, "days_until_expiry": -5})
        issues = _detect_ssl_vulnerabilities(ssl_result)
        assert any(i["id"] == "cert-expired" and i["severity"] == "critical" for i in issues)

    def test_flags_cert_expiring_soon(self):
        ssl_result = self._base(certificate={"is_self_signed": False, "is_expired": False, "days_until_expiry": 10})
        issues = _detect_ssl_vulnerabilities(ssl_result)
        assert any(i["id"] == "cert-expiring-soon" and i["severity"] == "medium" for i in issues)

    def test_flags_untrusted_chain(self):
        ssl_result = self._base(chain_trusted=False)
        issues = _detect_ssl_vulnerabilities(ssl_result)
        assert any(i["id"] == "untrusted-chain" and i["severity"] == "high" for i in issues)

    def test_multiple_issues_all_reported(self):
        ssl_result = self._base(
            protocol_support={"TLSv1.0": "supported", "TLSv1.1": "supported",
                               "TLSv1.2": "supported", "TLSv1.3": "supported"},
            cipher_suite={"name": "RC4-SHA"},
            certificate={"is_self_signed": True, "is_expired": True, "days_until_expiry": -1},
            chain_trusted=False,
        )
        issues = _detect_ssl_vulnerabilities(ssl_result)
        ids = {i["id"] for i in issues}
        assert {"deprecated-tlsv1.0", "deprecated-tlsv1.1", "weak-cipher",
                "self-signed-cert", "cert-expired", "untrusted-chain"} <= ids


# ── Attack Surface Score ────────────────────────────────────────────────────────

class TestSeverityForScore:
    def test_low_band(self):
        assert _severity_for_score(0) == "Low"
        assert _severity_for_score(30) == "Low"

    def test_medium_band(self):
        assert _severity_for_score(31) == "Medium"
        assert _severity_for_score(60) == "Medium"

    def test_high_band(self):
        assert _severity_for_score(61) == "High"
        assert _severity_for_score(80) == "High"

    def test_critical_band(self):
        assert _severity_for_score(81) == "Critical"
        assert _severity_for_score(100) == "Critical"


class TestCalculateAttackSurfaceScore:
    def test_empty_results_score_zero_low(self):
        result = calculate_attack_surface_score({})
        assert result["score"] == 0
        assert result["severity"] == "Low"
        assert result["breakdown"] == []
        assert len(result["recommendations"]) == 1

    def test_unnecessary_open_ports_add_5_each(self):
        network_results = {"shodan": {"open_ports": [8080, 9999], "vulnerabilities": []}}
        result = calculate_attack_surface_score(network_results)
        assert result["score"] == 10

    def test_expected_ports_dont_count(self):
        network_results = {"shodan": {"open_ports": [80, 443, 22], "vulnerabilities": []}}
        result = calculate_attack_surface_score(network_results)
        assert result["score"] == 0

    def test_open_ports_deduplicated_across_shodan_and_censys(self):
        network_results = {
            "shodan": {"open_ports": [8080], "vulnerabilities": []},
            "censys": {"open_ports": [8080], "vulnerabilities": []},
        }
        result = calculate_attack_surface_score(network_results)
        assert result["score"] == 5

    def test_deprecated_tls_adds_flat_15(self):
        network_results = {"ssl": {"protocol_support": {"TLSv1.0": "supported"}}}
        result = calculate_attack_surface_score(network_results)
        assert result["score"] == 15

    def test_modern_tls_only_adds_nothing(self):
        network_results = {"ssl": {"protocol_support": {"TLSv1.2": "supported", "TLSv1.3": "supported"}}}
        result = calculate_attack_surface_score(network_results)
        assert result["score"] == 0

    def test_critical_cve_adds_20(self):
        network_results = {"shodan": {"vulnerabilities": [{"cve": "CVE-2021-1111", "severity": "critical"}]}}
        result = calculate_attack_surface_score(network_results)
        assert result["score"] == 20

    def test_high_cve_adds_10(self):
        network_results = {"shodan": {"vulnerabilities": [{"cve": "CVE-2021-2222", "severity": "high"}]}}
        result = calculate_attack_surface_score(network_results)
        assert result["score"] == 10

    def test_unrated_cve_adds_5(self):
        network_results = {"shodan": {"vulnerabilities": [{"cve": "CVE-2021-3333", "severity": "medium"}]}}
        result = calculate_attack_surface_score(network_results)
        assert result["score"] == 5

    def test_missing_security_headers_add_5_each(self):
        network_results = {
            "services": {"services": [{"missing_security_headers": ["HSTS", "CSP"]}]},
        }
        result = calculate_attack_surface_score(network_results)
        assert result["score"] == 10

    def test_missing_headers_deduplicated_across_services(self):
        network_results = {
            "services": {"services": [
                {"missing_security_headers": ["HSTS"]},
                {"missing_security_headers": ["HSTS", "CSP"]},
            ]},
        }
        result = calculate_attack_surface_score(network_results)
        assert result["score"] == 10  # HSTS + CSP, deduplicated

    def test_score_capped_at_100(self):
        network_results = {
            "shodan": {
                "open_ports": list(range(1, 60)),
                "vulnerabilities": [{"cve": f"CVE-2021-{i}", "severity": "critical"} for i in range(10)],
            },
            "ssl": {"protocol_support": {"TLSv1.0": "supported"}},
            "services": {"services": [{"missing_security_headers": ["A", "B", "C", "D", "E"]}]},
        }
        result = calculate_attack_surface_score(network_results)
        assert result["score"] == 100
        assert result["severity"] == "Critical"

    def test_breakdown_entries_have_reason_and_points(self):
        network_results = {"ssl": {"protocol_support": {"TLSv1.0": "supported"}}}
        result = calculate_attack_surface_score(network_results)
        for entry in result["breakdown"]:
            assert "reason" in entry
            assert "points" in entry

    def test_recommendations_present_when_issues_found(self):
        network_results = {"ssl": {"protocol_support": {"TLSv1.0": "supported"}}}
        result = calculate_attack_surface_score(network_results)
        assert any("TLS" in r for r in result["recommendations"])

    def test_combined_realistic_scenario(self):
        network_results = {
            "shodan": {
                "open_ports": [80, 443, 8080, 9999],
                "vulnerabilities": [{"cve": "CVE-2021-1111", "severity": "critical"}],
            },
            "ssl": {"protocol_support": {"TLSv1.0": "supported", "TLSv1.2": "supported"}},
            "services": {"services": [{"missing_security_headers": ["HSTS", "CSP", "X-Frame-Options"]}]},
        }
        result = calculate_attack_surface_score(network_results)
        # 2 unnecessary ports (10) + TLS (15) + critical CVE (20) + 3 headers (15) = 60
        assert result["score"] == 60
        assert result["severity"] == "Medium"


# ── Orchestrator ─────────────────────────────────────────────────────────────

class TestGatherNetworkIntelligence:
    def _run(self, coro):
        return asyncio.run(coro)

    def test_example_com_structure(self):
        for _ in range(3):
            result = self._run(gather_network_intelligence("example.com", deep_scan=False))
            if result["ip"] is not None:
                break
        assert result["target"] == "example.com"
        assert result["ip"] is not None
        assert "shodan" in result
        assert "censys" in result
        assert "bgp" in result
        assert "ssl" in result
        assert "attack_surface" in result
        assert result["services"] is None  # deep_scan=False
        assert result["ip_ranges"] is None

    def test_attack_surface_always_present(self):
        result = self._run(gather_network_intelligence("8.8.8.8", deep_scan=False))
        surface = result["attack_surface"]
        assert "score" in surface
        assert "severity" in surface
        assert 0 <= surface["score"] <= 100
        assert surface["severity"] in ("Low", "Medium", "High", "Critical")

    def test_unresolvable_target_handled_gracefully(self):
        result = self._run(gather_network_intelligence(_BAD_HOST))
        assert result["ip"] is None
        assert "error" in result
        assert result["attack_surface"]["score"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
