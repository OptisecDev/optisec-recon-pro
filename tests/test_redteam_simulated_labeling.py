"""
Tests for the "Simulated" labeling of Phase 2/4/5/6 findings from
modules/ai_advanced/autonomous_redteam.py's _simulate_phase_findings()
(Public-Claims Audit follow-up).

start_autonomous_simulation() already tags these findings simulated=True
with a bilingual note/note_ar (see tests/test_autonomous_redteam_recon.py)
so the API output has always carried the flag. This file covers the two
places that were still silently presenting simulated findings as real:

1. web/templates/autonomous_redteam.html's renderResults() — the JS that
   renders findings for a freshly-launched or previously-viewed session —
   never surfaced finding.simulated, so a viewer saw "SQL Injection /
   CRITICAL" with no indication phases 2/4/5/6 aren't backed by a real
   engine.
2. modules/report/pdf_generator.py's finding heading — used by POST
   /api/report (a real, delivered PDF feature) — printed only "[severity]
   type", dropping the simulated tag if such a finding were ever included
   in a PDF's vuln_findings list.

There's no JS test runner in this repo, so (1) is a static-source
regression guard (same pattern as tests/test_threat_feed_xss_escaping.py),
while (2) is a direct unit test of the extracted _finding_heading() helper.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.report.pdf_generator import _finding_heading

TEMPLATE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "web", "templates", "autonomous_redteam.html",
)


def _read_template() -> str:
    with open(TEMPLATE_PATH, encoding="utf-8") as f:
        return f.read()


# ── UI: renderResults() must surface the simulated flag ──────────────────────

def test_render_results_checks_finding_simulated_flag():
    src = _read_template()
    fn = src.split("function renderResults(data)")[1].split("\nasync function")[0]
    assert "f.simulated" in fn


def test_render_results_shows_simulated_label():
    src = _read_template()
    fn = src.split("function renderResults(data)")[1].split("\nasync function")[0]
    assert "Simulated" in fn


# ── PDF report: _finding_heading() must tag simulated findings ───────────────

def test_finding_heading_tags_simulated_finding():
    finding = {"vuln": "SQL Injection", "severity": "CRITICAL", "simulated": True}
    heading = _finding_heading(finding, 1)
    assert "SIMULATED" in heading
    assert "SQL Injection" in heading
    assert "CRITICAL" in heading


def test_finding_heading_does_not_tag_real_finding():
    finding = {"vuln": "Open Ports Detected", "severity": "LOW", "source_module": "port_scanner"}
    heading = _finding_heading(finding, 1)
    assert "SIMULATED" not in heading


def test_finding_heading_falls_back_to_vuln_scanner_type_key():
    """Regular vuln-scanner findings (POST /api/report's existing callers)
    use a "type" key, not autonomous_redteam's "vuln" -- must keep working."""
    finding = {"type": "Reflected XSS", "severity": "MEDIUM"}
    heading = _finding_heading(finding, 2)
    assert "Reflected XSS" in heading
    assert "SIMULATED" not in heading


def test_finding_heading_prefers_type_over_vuln_when_both_present():
    finding = {"type": "Real Type", "vuln": "Should Not Appear", "severity": "LOW"}
    heading = _finding_heading(finding, 1)
    assert "Real Type" in heading
    assert "Should Not Appear" not in heading
