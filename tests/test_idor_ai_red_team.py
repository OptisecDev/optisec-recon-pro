"""IDOR tests for web/routers/ai_security.py's AI Red Team engagement
endpoints (modules/ai_advanced/red_team.py).

Found during the 2026-09-01 cross-user IDOR audit. Engagements
(target/scope/objectives/rules_of_engagement/findings -- the same
sensitivity class as a Scan or Report, both of which are correctly
per-user scoped elsewhere in this codebase) are stored in one shared
data/red_team_engagements.json list with no user_id field at all:

- GET /ai-security/api/red-team/engagements               -- lists ALL, unfiltered
- GET /ai-security/api/red-team/engagements/{id}           -- fetches ANY by id
- POST /ai-security/api/red-team/engagements/{id}/findings -- appends a finding
  to ANY engagement, no owner check

Same direct-router-call convention as
tests/test_idor_autonomous_rt_sessions.py; the module's ENGAGEMENTS_FILE
is monkeypatched to an isolated tmp_path file.
"""

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi import HTTPException

from web.models import User
import web.routers.ai_security as ai_security_router
import modules.ai_advanced.red_team as red_team_module


def _run(coro):
    return asyncio.run(coro)


def _fake_user(user_id: int, role: str = "analyst") -> User:
    return User(id=user_id, username=f"u{user_id}", email=f"u{user_id}@example.com",
                password_hash="x", role=role, subscription_tier="enterprise")


@pytest.fixture
def isolated_engagements(tmp_path, monkeypatch):
    data_file = tmp_path / "red_team_engagements.json"
    monkeypatch.setattr(red_team_module, "ENGAGEMENTS_FILE", data_file)
    return data_file


def _seed_engagement(data_file, engagement_id: str, user_id: int, target: str) -> None:
    engagement = {
        "id": engagement_id,
        "target": target,
        "user_id": user_id,
        "scope": [target],
        "objectives": ["Assess perimeter"],
        "rules_of_engagement": "No DoS",
        "status": "planned",
        "findings": [],
    }
    data_file.parent.mkdir(parents=True, exist_ok=True)
    data_file.write_text(json.dumps([engagement]))


class TestEngagementListIsolation:
    def test_attacker_cannot_see_victims_engagement_in_list(self, isolated_engagements):
        _seed_engagement(isolated_engagements, "RT-VICTIM-1", user_id=999, target="victim-corp.example.com")

        async def go():
            return await ai_security_router.list_engagements_api(user=_fake_user(1))
        result = _run(go())
        ids = [e["id"] for e in result["engagements"]]
        assert "RT-VICTIM-1" not in ids, "IDOR: attacker's engagement list includes another user's engagement"

    def test_owner_sees_own_engagement_in_list(self, isolated_engagements):
        _seed_engagement(isolated_engagements, "RT-OWNER-1", user_id=1, target="mine.example.com")

        async def go():
            return await ai_security_router.list_engagements_api(user=_fake_user(1))
        result = _run(go())
        ids = [e["id"] for e in result["engagements"]]
        assert "RT-OWNER-1" in ids


class TestEngagementGetOwnership:
    def test_attacker_cannot_fetch_victims_engagement_by_id(self, isolated_engagements):
        _seed_engagement(isolated_engagements, "RT-VICTIM-2", user_id=999, target="victim-corp.example.com")

        async def go():
            return await ai_security_router.get_engagement_api(engagement_id="RT-VICTIM-2", user=_fake_user(1))
        with pytest.raises(HTTPException) as exc_info:
            _run(go())
        assert exc_info.value.status_code == 404, (
            f"IDOR: attacker fetched another user's red-team engagement (got {exc_info.value.status_code})"
        )

    def test_admin_can_fetch_any_engagement(self, isolated_engagements):
        _seed_engagement(isolated_engagements, "RT-VICTIM-3", user_id=999, target="victim-corp.example.com")

        async def go():
            return await ai_security_router.get_engagement_api(engagement_id="RT-VICTIM-3", user=_fake_user(2, role="admin"))
        result = _run(go())
        assert result["id"] == "RT-VICTIM-3"


class TestLogFindingOwnership:
    def test_attacker_cannot_append_finding_to_victims_engagement(self, isolated_engagements):
        _seed_engagement(isolated_engagements, "RT-VICTIM-4", user_id=999, target="victim-corp.example.com")

        class _FakeRequest:
            async def json(self):
                return {"title": "planted finding", "severity": "critical"}

        async def go():
            return await ai_security_router.log_finding(
                engagement_id="RT-VICTIM-4", request=_FakeRequest(), user=_fake_user(1),
            )
        with pytest.raises(HTTPException) as exc_info:
            _run(go())
        assert exc_info.value.status_code == 404, (
            f"IDOR: attacker appended a finding to another user's engagement (got {exc_info.value.status_code})"
        )
