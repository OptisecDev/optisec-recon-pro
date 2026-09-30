"""Plan-provenance and honesty-labeling tests for the AI Red Team feature
(modules/ai_advanced/red_team.py, web/templates/red_team.html).

Root cause (Batch 3 audit): create_engagement() checks GROQ_API_KEY and
either calls _ai_generate_plan() or _template_plan() -- but
_ai_generate_plan() silently falls back to the same template on any Groq
failure, so nothing in the persisted engagement or the UI told an operator
whether a plan came from the LLM or the fixed offline template. Every
engagement now carries a "plan_source" field ("ai" | "template") so the
template can render an honest provenance badge instead of implying every
plan is AI-generated.

Mirrors tests/test_idor_ai_red_team.py's isolation pattern (ENGAGEMENTS_FILE
monkeypatched to a tmp_path file, direct module-level calls -- no HTTP
client / DB needed).
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import modules.ai_advanced.red_team as red_team_module


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def isolated_engagements(tmp_path, monkeypatch):
    data_file = tmp_path / "red_team_engagements.json"
    monkeypatch.setattr(red_team_module, "ENGAGEMENTS_FILE", data_file)
    return data_file


class TestPlanSourceTemplateFallback:
    def test_plan_source_is_template_when_groq_key_unset(self, isolated_engagements, monkeypatch):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)

        async def go():
            return await red_team_module.create_engagement(
                target="example.com", scope=["example.com"], objectives=["test"],
                categories=["reconnaissance"], user_id=1,
            )
        eng = _run(go())
        assert eng["plan_source"] == "template"

    def test_plan_source_is_template_when_groq_call_raises(self, isolated_engagements, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "fake-key-for-test")

        async def _boom(*a, **kw):
            raise RuntimeError("simulated Groq outage")
        monkeypatch.setattr(red_team_module, "call_groq_async_with_retry", _boom)

        async def go():
            return await red_team_module.create_engagement(
                target="example.com", scope=["example.com"], objectives=["test"],
                categories=["reconnaissance"], user_id=1,
            )
        eng = _run(go())
        assert eng["plan_source"] == "template"


class TestPlanSourceAI:
    def test_plan_source_is_ai_on_successful_mocked_groq_call(self, isolated_engagements, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "fake-key-for-test")

        fake_plan = {
            "phases": [{"phase_name": "Recon", "duration_days": 1, "techniques": ["T1595"],
                        "tools": ["nmap"], "success_criteria": "asset map built", "deliverables": ["report"]}],
            "estimated_risk": "critical",
            "estimated_duration_days": 1,
            "key_attack_vectors": ["weak auth"],
            "detection_evasion": [],
            "pivot_points": [],
            "executive_summary": "mocked AI plan",
        }

        async def _fake_retry(func, *a, **kw):
            return fake_plan
        monkeypatch.setattr(red_team_module, "call_groq_async_with_retry", _fake_retry)

        async def go():
            return await red_team_module.create_engagement(
                target="example.com", scope=["example.com"], objectives=["test"],
                categories=["reconnaissance"], user_id=1,
            )
        eng = _run(go())
        assert eng["plan_source"] == "ai"
        assert eng["plan"]["executive_summary"] == "mocked AI plan"
        assert eng["risk_rating"] == "critical"

    def test_plan_source_persisted_to_engagements_file(self, isolated_engagements, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "fake-key-for-test")

        async def _fake_retry(func, *a, **kw):
            return {"estimated_risk": "low", "phases": []}
        monkeypatch.setattr(red_team_module, "call_groq_async_with_retry", _fake_retry)

        async def go():
            return await red_team_module.create_engagement(
                target="example.com", scope=["example.com"], objectives=["test"],
                categories=["reconnaissance"], user_id=1,
            )
        _run(go())

        stored = red_team_module.list_engagements()
        assert stored[0]["plan_source"] == "ai"


# ── Template honesty: provenance badge, risk-estimate relabel, disclaimer ────

TEMPLATE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "web", "templates", "red_team.html",
)


def _read_template() -> str:
    with open(TEMPLATE_PATH, encoding="utf-8") as f:
        return f.read()


class TestRedTeamTemplateHonesty:
    def test_plan_source_badge_present_in_list_card(self):
        html = _read_template()
        assert "eng.plan_source" in html
        assert "AI-generated" in html
        assert "Template (offline)" in html

    def test_plan_source_badge_present_in_detail_view(self):
        html = _read_template()
        assert "data.plan_source" in html

    def test_risk_badge_relabeled_as_estimate_not_measurement(self):
        html = _read_template()
        assert "Est. Risk:" in html
        assert "EST. RISK:" in html
        assert "not a measured or verified assessment of the target" in html

    def test_standing_plan_disclaimer_present(self):
        html = _read_template()
        assert html.count("not a verified risk assessment") >= 2
        assert "not the result of any actual scan of the target" in html

    def test_loading_message_does_not_unconditionally_claim_ai(self):
        html = _read_template()
        assert "AI generating red team plan" not in html
