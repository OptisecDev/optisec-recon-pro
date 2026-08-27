"""
Tests for modules/ai_advanced/autonomous_redteam.py's Phase 1 (Reconnaissance)
real-scan integration and the simulated-finding tagging for Phases 2/4/5/6.

Before this change, start_autonomous_simulation()'s entire findings list came
from _simulate_phase_findings() — a fixed pool of ten canned vulnerabilities
selected deterministically by hashing target+attack_types, mislabeled as
Phase 1 (Reconnaissance) output. _simulate_phase_findings() itself is kept
unchanged (Phases 2/4/5/6 — Weaponization, Post-Exploitation, Lateral
Movement, Objective Completion — have no real engine behind them and won't
in this project), but its output is now tagged simulated=True with a
bilingual note/note_ar, while Phase 1 findings are built directly from
modules/recon's real scan functions (port_scanner, subdomains, ssl_analysis,
security_headers, whois_lookup, dns_lookup, nmap_scanner).

Phase 3 (Initial Access / web vuln scanning) has its own real-scan wiring and
its own test file (tests/test_autonomous_redteam_webscan.py) — the fixture
below stubs modules/vuln's scanners to no-ops purely so these Phase 1 tests
stay network-isolated and unaffected by Phase 3 running alongside it.
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


# ── Deterministic fake recon outputs (shape matches each real module's return) ──

FAKE_PORTS = {
    "target": "evil.example.com", "host": "evil.example.com", "ip": "203.0.113.5",
    "ports_scanned": 100,
    "open_ports": [
        {"port": 6379, "service": "Redis", "banner": "", "high_risk": True, "risk_label": "HIGH"},
        {"port": 80, "service": "HTTP", "banner": "", "high_risk": False, "risk_label": "LOW"},
    ],
    "open_count": 2, "high_risk_count": 1, "risk_score": 45, "risk_label": "MEDIUM",
    "notes": ["2 open ports found", "High-risk services exposed: 6379/Redis"],
}

FAKE_SSL = {
    "domain": "evil.example.com", "valid": False, "expired": True, "expiring_soon": False,
    "days_remaining": -10, "tls_version": "TLSv1.2", "risk_score": 60, "risk_label": "HIGH",
    "notes": ["Certificate has EXPIRED — visitors will see security warnings"],
}

FAKE_HEADERS = {
    "url": "https://evil.example.com", "status_code": 200, "security_score": 20, "grade": "F",
    "missing_headers": {"Content-Security-Policy": {}, "Strict-Transport-Security": {}},
    "present_headers": {}, "exposed_info_headers": {"Server": {"value": "nginx/1.18.0", "risk": "reveals stack"}},
    "risk_score": 80, "risk_label": "HIGH",
}

FAKE_SUBDOMAINS = [
    {"subdomain": "admin.evil.example.com", "ip": "203.0.113.6"},
    {"subdomain": "vpn.evil.example.com", "ip": "203.0.113.7"},
]

FAKE_WHOIS = {"domain_name": "evil.example.com", "emails": ["registrant@evil.example.com"]}
FAKE_DNS = {"A": ["203.0.113.5"], "AAAA": [], "MX": [], "NS": [], "TXT": ["v=spf1 -all"],
            "CNAME": [], "SOA": [], "SRV": []}
FAKE_NMAP = {"target": "evil.example.com", "state": "up", "hostname": "evil.example.com",
             "ports": [{"port": "22", "protocol": "tcp", "state": "open", "service": "ssh",
                        "product": "OpenSSH", "version": "8.9"}]}


@pytest.fixture(autouse=True)
def _patch_recon(monkeypatch):
    monkeypatch.setattr(ports_mod, "scan_ports", lambda *a, **k: FAKE_PORTS)
    monkeypatch.setattr(ssl_mod, "analyze_ssl", lambda *a, **k: FAKE_SSL)
    monkeypatch.setattr(headers_mod, "check_security_headers", lambda *a, **k: FAKE_HEADERS)
    monkeypatch.setattr(art, "enumerate_subdomains", lambda *a, **k: FAKE_SUBDOMAINS)
    monkeypatch.setattr(art, "whois_lookup", lambda *a, **k: FAKE_WHOIS)
    monkeypatch.setattr(art, "dns_lookup", lambda *a, **k: FAKE_DNS)
    monkeypatch.setattr(art, "nmap_scan", lambda *a, **k: FAKE_NMAP)
    # Phase 3 (web vuln scan) is out of scope for this file (see
    # tests/test_autonomous_redteam_webscan.py) — stub it out to no findings
    # so these Phase 1 tests stay network-isolated and unaffected by it.
    monkeypatch.setattr(xss_mod, "scan_xss", lambda *a, **k: [])
    monkeypatch.setattr(sqli_mod, "scan_sqli", lambda *a, **k: [])
    monkeypatch.setattr(ssrf_mod, "scan_ssrf", lambda *a, **k: [])
    monkeypatch.setattr(lfi_mod, "scan_lfi", lambda *a, **k: [])
    monkeypatch.setattr(redirect_mod, "scan_open_redirect", lambda *a, **k: [])


@pytest.fixture(autouse=True)
def _isolate_sessions_file(tmp_path, monkeypatch):
    monkeypatch.setattr(art, "DATA_FILE", tmp_path / "autonomous_rt_sessions.json")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)


class TestPhase1RealRecon:
    def test_findings_are_derived_from_mocked_recon_output_not_a_static_list(self):
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        findings = session["findings"]
        phase1 = [f for f in findings if f.get("phase") == 1]
        assert phase1, "expected at least one Phase 1 finding"

        # Every phase-1 finding's text traces back to the mocked recon data,
        # proving it was NOT pulled from the old hard-coded potential_findings pool.
        joined = " ".join(f["proof"] + f["endpoint"] + f["vuln"] for f in phase1)
        assert "6379" in joined and "Redis" in joined
        assert "admin.evil.example.com" in joined
        assert "registrant@evil.example.com" in joined
        assert "v=spf1 -all" in joined
        assert "nginx/1.18.0" in joined

        for f in phase1:
            assert f.get("simulated") is not True

    def test_changing_mocked_recon_output_changes_findings(self, monkeypatch):
        monkeypatch.setattr(ports_mod, "scan_ports", lambda *a, **k: {
            **FAKE_PORTS,
            "open_ports": [
                {"port": 3389, "service": "RDP", "banner": "", "high_risk": True, "risk_label": "HIGH"},
            ],
            "high_risk_count": 1,
        })
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        phase1 = [f for f in session["findings"] if f.get("phase") == 1]
        joined = " ".join(f["proof"] + f["endpoint"] for f in phase1)
        assert "3389" in joined
        assert "6379" not in joined

    def test_recon_data_stored_on_session(self):
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        assert session["recon_data"]["ports"] == FAKE_PORTS
        assert session["recon_data"]["whois"] == FAKE_WHOIS
        assert session["recon_data"]["nmap"] == FAKE_NMAP

    def test_port_scanner_error_produces_low_severity_finding_not_a_crash(self, monkeypatch):
        monkeypatch.setattr(ports_mod, "scan_ports", lambda *a, **k: {
            "target": "evil.example.com", "error": "DNS resolution failed: [Errno -2]",
        })
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        phase1 = [f for f in session["findings"] if f.get("phase") == 1]
        assert any(f["vuln"] == "Port Scan Failed" and f["severity"] == "LOW" for f in phase1)


class TestSimulatedPhasesTagging:
    def test_every_non_phase1_finding_is_tagged_simulated(self):
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        simulated = [f for f in session["findings"] if f.get("phase") != 1]
        assert simulated, "expected simulated findings representing phases 2/4/5/6"
        for f in simulated:
            assert f["simulated"] is True
            assert f["phase"] in (2, 4, 5, 6)
            assert f["note"]
            assert f["note_ar"]
            # bilingual: note_ar must actually carry Arabic script
            assert any("؀" <= ch <= "ۿ" for ch in f["note_ar"])

    def test_phase1_findings_are_never_tagged_simulated(self):
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        phase1 = [f for f in session["findings"] if f.get("phase") == 1]
        assert phase1
        for f in phase1:
            assert "simulated" not in f or f["simulated"] is False

    def test_finding_ids_are_unique_across_combined_list(self):
        session = _run(art.start_autonomous_simulation("evil.example.com", ["web"]))
        ids = [f["id"] for f in session["findings"]]
        assert len(ids) == len(set(ids))

    def test_simulate_phase_findings_logic_itself_is_unchanged(self):
        # _simulate_phase_findings() must keep producing its original,
        # untagged shape — tagging happens as a post-processing step in
        # start_autonomous_simulation(), not inside the function itself.
        raw = art._simulate_phase_findings("evil.example.com", ["web"], "medium")
        assert raw
        for f in raw:
            assert "simulated" not in f
            assert "note" not in f
            assert "note_ar" not in f
