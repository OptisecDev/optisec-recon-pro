"""
Tests for modules/ai_advanced/autonomous_redteam.py's Phase 3 (Initial Access)
real-scan integration.

Before this change, start_autonomous_simulation() had no real Phase 3 output
at all — every finding besides Phase 1 (Reconnaissance) came from
_simulate_phase_findings(), a fixed pool of ten canned vulnerabilities cycled
across Phases 2/4/5/6 only. Phase 3 findings are now built directly from
modules/vuln's real scan functions (xss, sqli, ssrf, lfi, open_redirect), the
same functions web/app.py's scan task runner calls, and only
verdict == "CONFIRMED" results (waf_aware_classifier.py's should_report gate)
are turned into findings.

Phase 1 and the simulated Phases 2/4/5/6 are untouched here — see
tests/test_autonomous_redteam_recon.py.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import modules.ai_advanced.autonomous_redteam as art
import modules.recon.ssl_analysis as ssl_mod
import modules.recon.security_headers as headers_mod
import modules.recon.port_scanner as ports_mod
import modules.vuln.xss as xss_mod
import modules.vuln.sqli as sqli_mod
import modules.vuln.ssrf as ssrf_mod
import modules.vuln.lfi as lfi_mod
import modules.vuln.open_redirect as redirect_mod


def _run(coro):
    return asyncio.run(coro)


# ── Deterministic fake recon outputs, so Phase 1 stays out of the way ────────

FAKE_PORTS = {"target": "evil.example.com", "host": "evil.example.com", "open_ports": [],
              "open_count": 0, "high_risk_count": 0, "risk_score": 0, "risk_label": "LOW", "notes": []}
FAKE_SSL = {"domain": "evil.example.com", "valid": True, "expired": False, "expiring_soon": False,
            "risk_score": 0, "risk_label": "LOW", "notes": []}
FAKE_HEADERS = {"url": "https://evil.example.com", "status_code": 200, "security_score": 100,
                "grade": "A", "missing_headers": {}, "present_headers": {}, "exposed_info_headers": {},
                "risk_score": 0, "risk_label": "LOW"}


# ── Fake vuln-scan outputs (shape matches each real module's return dicts:
# type/severity/url/parameter/payload/evidence/waf_detected/verdict) ────────

def _fake_xss_confirmed(url):
    return [{
        "type": "XSS", "severity": "High", "url": f"{url}?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "parameter": "q", "payload": "<script>alert(1)</script>",
        "evidence": "Raw payload reflected unencoded, HTTP 200, no WAF detected",
        "waf_detected": None, "verdict": "CONFIRMED", "status_code": 200, "response_body": "...",
    }]


def _fake_xss_waf_blocked(url):
    return [{
        "type": "XSS", "severity": "Medium", "url": f"{url}?q=%3Cscript%3E",
        "parameter": "q", "payload": "<script>alert(1)</script>",
        "evidence": "Blocked by Cloudflare (HTTP 403)",
        "waf_detected": "Cloudflare", "verdict": "WAF_BLOCKED", "status_code": 403, "response_body": "...",
    }]


def _fake_sqli_confirmed(url):
    return [{
        "type": "SQL Injection", "severity": "Critical", "url": f"{url}?id=1'",
        "parameter": "id", "payload": "' UNION SELECT NULL--",
        "evidence": "SQL error signature detected: 'you have an error in your sql syntax'",
        "waf_detected": None, "verdict": "CONFIRMED", "status_code": 200, "response_body": "...",
    }]


@pytest.fixture(autouse=True)
def _patch_recon(monkeypatch):
    monkeypatch.setattr(ports_mod, "scan_ports", lambda *a, **k: FAKE_PORTS)
    monkeypatch.setattr(ssl_mod, "analyze_ssl", lambda *a, **k: FAKE_SSL)
    monkeypatch.setattr(headers_mod, "check_security_headers", lambda *a, **k: FAKE_HEADERS)
    monkeypatch.setattr(art, "enumerate_subdomains", lambda *a, **k: [])
    monkeypatch.setattr(art, "whois_lookup", lambda *a, **k: {"emails": []})
    monkeypatch.setattr(art, "dns_lookup", lambda *a, **k: {"TXT": []})
    monkeypatch.setattr(art, "nmap_scan", lambda *a, **k: {"ports": []})


@pytest.fixture(autouse=True)
def _isolate_sessions_file(tmp_path, monkeypatch):
    monkeypatch.setattr(art, "DATA_FILE", tmp_path / "autonomous_rt_sessions.json")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)


@pytest.fixture(autouse=True)
def _stub_all_vuln_scans_empty(monkeypatch):
    """Default: every vuln scanner returns no results. Individual tests
    override the ones they care about."""
    monkeypatch.setattr(xss_mod, "scan_xss", lambda *a, **k: [])
    monkeypatch.setattr(sqli_mod, "scan_sqli", lambda *a, **k: [])
    monkeypatch.setattr(ssrf_mod, "scan_ssrf", lambda *a, **k: [])
    monkeypatch.setattr(lfi_mod, "scan_lfi", lambda *a, **k: [])
    monkeypatch.setattr(redirect_mod, "scan_open_redirect", lambda *a, **k: [])


class TestPhase3RealWebScan:
    def test_confirmed_finding_is_derived_from_mocked_scan_output_not_a_static_list(self, monkeypatch):
        monkeypatch.setattr(xss_mod, "scan_xss", lambda url: _fake_xss_confirmed(url))
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        phase3 = [f for f in session["findings"] if f.get("phase") == 3]

        assert len(phase3) == 1
        f = phase3[0]
        assert "XSS" in f["vuln"]
        assert "parameter: q" in f["vuln"]
        assert f["severity"] == "HIGH"
        assert f["cvss"] == art.SEVERITY_CVSS["HIGH"]
        assert "Raw payload reflected unencoded" in f["proof"]
        assert f["technique"] == "T1059.007"
        assert f["source_module"] == "xss"
        assert f.get("simulated") is not True

    def test_changing_mocked_scan_output_changes_findings(self, monkeypatch):
        monkeypatch.setattr(sqli_mod, "scan_sqli", lambda url: _fake_sqli_confirmed(url))
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        phase3 = [f for f in session["findings"] if f.get("phase") == 3]

        assert len(phase3) == 1
        assert "SQL Injection" in phase3[0]["vuln"]
        assert phase3[0]["severity"] == "CRITICAL"
        assert phase3[0]["technique"] == "T1190"

    def test_only_confirmed_verdicts_become_findings(self, monkeypatch):
        # WAF_BLOCKED must never surface as a finding, even though the
        # scanner returned data for it.
        monkeypatch.setattr(xss_mod, "scan_xss", lambda url: _fake_xss_waf_blocked(url))
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        phase3 = [f for f in session["findings"] if f.get("phase") == 3]
        assert phase3 == []

    def test_mixed_confirmed_and_non_confirmed_only_keeps_confirmed(self, monkeypatch):
        monkeypatch.setattr(xss_mod, "scan_xss", lambda url: _fake_xss_confirmed(url))
        monkeypatch.setattr(sqli_mod, "scan_sqli", lambda url: [
            {"type": "SQL Injection", "severity": None, "url": url, "parameter": "id",
             "payload": "' OR 1=1--", "evidence": "HTTP 404 — endpoint not reachable/valid, not a real test",
             "waf_detected": None, "verdict": "ENDPOINT_INVALID", "status_code": 404, "response_body": ""},
        ])
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        phase3 = [f for f in session["findings"] if f.get("phase") == 3]

        assert len(phase3) == 1
        assert "XSS" in phase3[0]["vuln"]

    def test_web_scan_data_stored_on_session(self, monkeypatch):
        monkeypatch.setattr(xss_mod, "scan_xss", lambda url: _fake_xss_confirmed(url))
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        assert session["web_scan_data"]["xss"][0]["type"] == "XSS"
        assert session["web_scan_data"]["xss"][0]["verdict"] == "CONFIRMED"
        assert session["web_scan_data"]["sqli"] == []

    def test_phase3_findings_are_never_tagged_simulated(self, monkeypatch):
        monkeypatch.setattr(xss_mod, "scan_xss", lambda url: _fake_xss_confirmed(url))
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        phase3 = [f for f in session["findings"] if f.get("phase") == 3]
        assert phase3
        for f in phase3:
            assert "simulated" not in f or f["simulated"] is False

    def test_risk_score_is_recomputed_from_the_actual_findings_list(self, monkeypatch):
        monkeypatch.setattr(sqli_mod, "scan_sqli", lambda url: _fake_sqli_confirmed(url))
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        phase3 = [f for f in session["findings"] if f.get("phase") == 3]
        assert len(phase3) == 1

        # risk_score must equal recomputing _calculate_risk_score() over the
        # session's own findings list (including the real Phase 3 finding) —
        # proving it's derived live, not a fixed/precomputed constant.
        assert session["risk_score"] == art._calculate_risk_score(session["findings"])

        # Dropping the confirmed Phase 3 finding must not increase the score
        # (it can only stay the same, if the total was already saturating the
        # 100-point cap, or drop).
        without_phase3 = [f for f in session["findings"] if f.get("phase") != 3]
        assert art._calculate_risk_score(without_phase3) <= session["risk_score"]

    def test_calculate_risk_score_weighs_confirmed_findings_by_severity(self):
        # Direct unit check, away from the 100-point cap and the simulated
        # pool's randomness: adding one CRITICAL Phase 3 finding must raise
        # the score by exactly its severity weight.
        base = [{"severity": "LOW", "phase": 1}]
        with_phase3_critical = base + [{"severity": "CRITICAL", "phase": 3}]
        assert (
            art._calculate_risk_score(with_phase3_critical) - art._calculate_risk_score(base)
            == 25
        )

    def test_no_web_scan_runs_when_web_and_sqli_not_in_attack_types(self, monkeypatch):
        calls = []
        monkeypatch.setattr(xss_mod, "scan_xss", lambda url: (calls.append(url), _fake_xss_confirmed(url))[1])
        session = _run(art.start_autonomous_simulation("evil.example.com", ["network"]))
        assert calls == []
        assert session["web_scan_data"] == {}
        assert [f for f in session["findings"] if f.get("phase") == 3] == []


class TestSimulatedPhasesStillUnaffected:
    def test_simulated_phases_still_only_cycle_2_4_5_6(self, monkeypatch):
        monkeypatch.setattr(xss_mod, "scan_xss", lambda url: _fake_xss_confirmed(url))
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        simulated = [f for f in session["findings"] if f.get("simulated") is True]
        assert simulated
        for f in simulated:
            assert f["phase"] in (2, 4, 5, 6)
