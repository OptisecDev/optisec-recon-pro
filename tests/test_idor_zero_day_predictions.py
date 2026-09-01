"""IDOR test for web/routers/ai_security.py's zero-day prediction history
(modules/ai_advanced/zero_day.py).

Found during the 2026-09-01 cross-user IDOR audit. Every call to
POST /ai-security/api/zero-day/predict persists the full query
(target_software/version -- client-supplied free text, which can name an
internal/unreleased product) plus the AI's risk analysis into one shared
data/zero_day_predictions.json list with no user_id field.
GET /ai-security/api/zero-day/predictions returns that whole list to any
authenticated user with the zero_day_predict feature entitlement,
regardless of who ran the query.

Same direct-router-call convention as tests/test_idor_ai_red_team.py; the
module's PREDICTIONS_FILE is monkeypatched to an isolated tmp_path file.
"""

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from web.models import User
import web.routers.ai_security as ai_security_router
import modules.ai_advanced.zero_day as zero_day_module


def _run(coro):
    return asyncio.run(coro)


def _fake_user(user_id: int, role: str = "analyst") -> User:
    return User(id=user_id, username=f"u{user_id}", email=f"u{user_id}@example.com",
                password_hash="x", role=role, subscription_tier="enterprise")


@pytest.fixture
def isolated_predictions(tmp_path, monkeypatch):
    data_file = tmp_path / "zero_day_predictions.json"
    monkeypatch.setattr(zero_day_module, "PREDICTIONS_FILE", data_file)
    return data_file


def _seed_prediction(data_file, user_id: int, target_software: str) -> None:
    prediction = {
        "target_software": target_software,
        "version": "3.2-internal",
        "user_id": user_id,
        "risk_score": 0.9,
        "risk_level": "critical",
    }
    data_file.parent.mkdir(parents=True, exist_ok=True)
    data_file.write_text(json.dumps([prediction]))


class TestPredictionListIsolation:
    def test_attacker_cannot_see_victims_prediction_in_list(self, isolated_predictions):
        _seed_prediction(isolated_predictions, user_id=999, target_software="victim-internal-tool")

        async def go():
            return await ai_security_router.get_predictions(user=_fake_user(1))
        result = _run(go())
        names = [p["target_software"] for p in result["predictions"]]
        assert "victim-internal-tool" not in names, (
            "IDOR: attacker's zero-day prediction list includes another user's query"
        )

    def test_owner_sees_own_prediction_in_list(self, isolated_predictions):
        _seed_prediction(isolated_predictions, user_id=1, target_software="my-own-tool")

        async def go():
            return await ai_security_router.get_predictions(user=_fake_user(1))
        result = _run(go())
        names = [p["target_software"] for p in result["predictions"]]
        assert "my-own-tool" in names

    def test_admin_sees_all_predictions(self, isolated_predictions):
        _seed_prediction(isolated_predictions, user_id=999, target_software="victim-internal-tool")

        async def go():
            return await ai_security_router.get_predictions(user=_fake_user(2, role="admin"))
        result = _run(go())
        names = [p["target_software"] for p in result["predictions"]]
        assert "victim-internal-tool" in names
