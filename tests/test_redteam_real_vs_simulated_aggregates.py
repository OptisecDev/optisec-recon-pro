"""
PRIORITY 1, items 1-2 of the live-walkthrough audit (BATCH 2):

Before this change, modules/ai_advanced/autonomous_redteam.py's risk score,
executive-summary Total/Critical/High/Medium counters, and compliance
verdicts (GDPR/PCI_DSS/SOC2/ISO27001) were all computed over the FULL
findings list — real recon/scan output blended with the ten-item
_simulate_phase_findings() pool for Phases 2/4/5/6. In the live run, a
single simulated "Weak JWT Secret" (CVSS 9.1) drove the score to 100/100
CRITICAL and a PCI_DSS "NON-COMPLIANT" / SOC2 "MATERIAL WEAKNESS" verdict,
even though nothing was actually exploited on the target.

This file proves risk_score, generate_pentest_report()'s executive_summary
counters, and its compliance_impact block are all now derived from REAL
findings only, with simulated findings reported separately and excluded
from every one of those aggregates.
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


# ── Real recon/scan output is all LOW/clean — nothing here should ever ───────
# produce a CRITICAL or HIGH real finding.

FAKE_PORTS = {"target": "evil.example.com", "host": "evil.example.com", "open_ports": [],
              "open_count": 0, "high_risk_count": 0, "risk_score": 0, "risk_label": "LOW", "notes": []}
FAKE_SSL = {"domain": "evil.example.com", "valid": True, "expired": False, "expiring_soon": False,
            "risk_score": 0, "risk_label": "LOW", "notes": []}
FAKE_HEADERS = {"url": "https://evil.example.com", "status_code": 200, "security_score": 100,
                "grade": "A", "missing_headers": {}, "present_headers": {}, "exposed_info_headers": {},
                "risk_score": 0, "risk_label": "LOW"}

# The single simulated finding used across this file: CRITICAL, matching the
# live-walkthrough "Weak JWT Secret" CVSS 9.1 case.
_SIMULATED_CRITICAL = [{
    "vuln": "Weak JWT Secret", "severity": "CRITICAL", "endpoint": "https://evil.example.com/api/auth",
    "technique": "T1552", "cvss": 9.1, "cve": "N/A",
    "proof": "JWT signed with 'secret' — forged admin token accepted",
}]


@pytest.fixture(autouse=True)
def _patch_recon(monkeypatch):
    monkeypatch.setattr(ports_mod, "scan_ports", lambda *a, **k: FAKE_PORTS)
    monkeypatch.setattr(ssl_mod, "analyze_ssl", lambda *a, **k: FAKE_SSL)
    monkeypatch.setattr(headers_mod, "check_security_headers", lambda *a, **k: FAKE_HEADERS)
    monkeypatch.setattr(art, "enumerate_subdomains", lambda *a, **k: {"subdomains": [], "unconfirmed": []})
    monkeypatch.setattr(art, "whois_lookup", lambda *a, **k: {"emails": []})
    monkeypatch.setattr(art, "dns_lookup", lambda *a, **k: {"TXT": []})
    monkeypatch.setattr(art, "nmap_scan", lambda *a, **k: {"ports": []})
    monkeypatch.setattr(xss_mod, "scan_xss", lambda *a, **k: [])
    monkeypatch.setattr(sqli_mod, "scan_sqli", lambda *a, **k: [])
    monkeypatch.setattr(ssrf_mod, "scan_ssrf", lambda *a, **k: [])
    monkeypatch.setattr(lfi_mod, "scan_lfi", lambda *a, **k: [])
    monkeypatch.setattr(redirect_mod, "scan_open_redirect", lambda *a, **k: [])


@pytest.fixture(autouse=True)
def _isolate_sessions_file(tmp_path, monkeypatch):
    monkeypatch.setattr(art, "DATA_FILE", tmp_path / "autonomous_rt_sessions.json")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)


@pytest.fixture(autouse=True)
def _one_simulated_critical(monkeypatch):
    """Force _simulate_phase_findings() to return exactly the CRITICAL Weak
    JWT scenario from the live walkthrough, deterministically."""
    monkeypatch.setattr(art, "_simulate_phase_findings", lambda *a, **k: [dict(f) for f in _SIMULATED_CRITICAL])


class TestRiskScoreExcludesSimulated:
    def test_risk_score_is_not_driven_by_a_simulated_critical(self):
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        real_findings = [f for f in session["findings"] if not f.get("simulated")]
        simulated = [f for f in session["findings"] if f.get("simulated")]

        assert simulated and simulated[0]["vuln"] == "Weak JWT Secret"
        # All real findings here are LOW/clean recon output — the score must
        # stay low, not jump to 100 because of the simulated CRITICAL.
        assert session["risk_score"] < 25
        assert session["risk_score"] == art._calculate_risk_score(real_findings)


class TestExecutiveSummaryCountersExcludeSimulated:
    def test_critical_count_is_zero_when_only_simulated_finding_is_critical(self):
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        exec_summary = session["report"]["executive_summary"]
        assert exec_summary["critical_count"] == 0
        assert exec_summary["overall_risk"] != "CRITICAL"

    def test_total_findings_counts_real_findings_only(self):
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        real_findings = [f for f in session["findings"] if not f.get("simulated")]
        exec_summary = session["report"]["executive_summary"]
        assert exec_summary["total_findings"] == len(real_findings)
        assert exec_summary["simulated_findings_count"] == 1

    def test_key_findings_never_names_the_simulated_critical(self):
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        exec_summary = session["report"]["executive_summary"]
        assert "Weak JWT Secret" not in exec_summary["key_findings"]

    def test_risk_score_note_states_verified_findings_only(self):
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        exec_summary = session["report"]["executive_summary"]
        assert "verified" in exec_summary["risk_score_note"].lower()
        assert any("؀" <= ch <= "ۿ" for ch in exec_summary["risk_score_note_ar"])


class TestComplianceImpactExcludesSimulated:
    def test_pci_dss_is_not_non_compliant_from_a_simulated_critical_alone(self):
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        compliance = session["report"]["compliance_impact"]
        assert "NON-COMPLIANT" not in compliance["PCI_DSS"]
        assert compliance["SOC2"] != "MATERIAL WEAKNESS"

    def test_assess_compliance_impact_direct_unit_check(self):
        # Direct check on the helper: passing only simulated-flagged findings
        # (as generate_pentest_report is careful never to do) would trip
        # has_critical; passing [] (the correct call after filtering) must not.
        assert art._assess_compliance_impact([])["PCI_DSS"] != "NON-COMPLIANT — unauthorized access vectors identified"
        assert art._assess_compliance_impact([{"severity": "CRITICAL", "vuln": "x"}])["PCI_DSS"].startswith("NON-COMPLIANT")


class TestNarrativeDoesNotCreditSimulatedFindings:
    def test_narrative_does_not_claim_access_was_achieved_via_the_simulated_finding(self):
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        narrative = session["report"]["attack_narrative"]
        assert "Weak JWT Secret" not in narrative
        assert "achieved via" not in narrative or "Weak JWT" not in narrative

    def test_narrative_mentions_no_confirmed_vulnerabilities_when_all_real_findings_are_low(self):
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        real_findings = [f for f in session["findings"] if not f.get("simulated")]
        narrative = session["report"]["attack_narrative"]
        if not any(f.get("severity") == "CRITICAL" for f in real_findings) and not real_findings:
            assert "no vulnerabilities" in narrative.lower() or "no critical" in narrative.lower()
