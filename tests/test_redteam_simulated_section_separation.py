"""
PRIORITY 1 item 1b/1c of the live-walkthrough audit (BATCH 2):
web/templates/autonomous_redteam.html's renderResults() must render
simulated findings in a section clearly separated from real findings
(title "Simulated Attack Scenarios — Demonstration Only", bilingual),
and the score banner must state it reflects verified findings only.

Static-source regression guard, same pattern as
tests/test_redteam_simulated_labeling.py — there's no JS test runner here.
"""
import os

TEMPLATE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "web", "templates", "autonomous_redteam.html",
)


def _render_results_fn() -> str:
    with open(TEMPLATE_PATH, encoding="utf-8") as f:
        src = f.read()
    return src.split("function renderResults(data)")[1].split("\nasync function")[0]


def test_findings_are_split_into_real_and_simulated_arrays():
    fn = _render_results_fn()
    assert "filter(f => !f.simulated)" in fn or "filter(f=>!f.simulated)" in fn
    assert "filter(f => f.simulated)" in fn or "filter(f=>f.simulated)" in fn


def test_simulated_section_has_bilingual_demonstration_only_title():
    fn = _render_results_fn()
    assert "Simulated Attack Scenarios" in fn
    assert "Demonstration Only" in fn
    assert any("؀" <= ch <= "ۿ" for ch in fn), "expected Arabic script somewhere in renderResults"


def test_simulated_section_states_excluded_from_counters():
    fn = _render_results_fn()
    assert "Excluded from the risk score" in fn


def test_headline_total_uses_real_findings_not_combined_list():
    fn = _render_results_fn()
    # The old bug used `findings.length` (the combined array) for the Total
    # stat. It must now use the real-findings-derived total.
    assert "totalReal" in fn
    assert "'Total','verified',totalReal" in fn.replace(" ", "") or "'Total','verified',totalReal,".replace(" ", "") in fn.replace(" ", "")


def test_score_banner_states_verified_findings_only():
    fn = _render_results_fn()
    assert "risk_score_note" in fn
    assert "verified findings only" in fn.lower()
