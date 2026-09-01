"""IDOR tests for web/routers/autonomous_rt.py's session endpoints.

Found during the 2026-09-01 cross-user IDOR audit. The router already has
check_target_ownership() gating POST /api/start (commit 33d933d, prior
session) -- but the *session* created by a successful start is never
tagged with the creating user's id at all in
modules/ai_advanced/autonomous_redteam.py's storage
(data/autonomous_rt_sessions.json is one shared list, no user_id field).
As a result, three endpoints leak every user's full recon/exploitation
session data to any other authenticated user with the autonomous_redteam
feature entitlement:

- GET /autonomous-redteam/api/sessions          -- lists ALL sessions, unfiltered
- GET /autonomous-redteam/api/sessions/{id}     -- fetches ANY session by id, no owner check
- POST /autonomous-redteam/api/generate-report/{id} -- generates a full pentest
  report from ANY session, no owner check

Mirrors tests/test_autonomous_rt_router.py's convention: call the route
handler functions directly with fake User objects, no HTTP layer. The
module's DATA_FILE is monkeypatched to an isolated tmp_path file so this
test never touches the real project's data/autonomous_rt_sessions.json.
"""

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi import HTTPException

from web.models import User
import web.routers.autonomous_rt as art_router
import modules.ai_advanced.autonomous_redteam as art_module


def _run(coro):
    return asyncio.run(coro)


def _fake_user(user_id: int, role: str = "analyst") -> User:
    return User(id=user_id, username=f"u{user_id}", email=f"u{user_id}@example.com",
                password_hash="x", role=role, subscription_tier="enterprise")


@pytest.fixture
def isolated_sessions(tmp_path, monkeypatch):
    data_file = tmp_path / "autonomous_rt_sessions.json"
    monkeypatch.setattr(art_module, "DATA_FILE", data_file)
    return data_file


def _seed_session(data_file, session_id: str, user_id: int, target: str) -> None:
    """Write a session dict directly to the isolated store, as if `user_id`
    had started it via POST /api/start. The real create flow (
    start_autonomous_simulation) runs live recon network calls, so tests
    inject the session shape directly rather than running it end to end."""
    session = {
        "id": session_id,
        "target": target,
        "user_id": user_id,
        "status": "completed",
        "findings": [{"id": "F001", "type": "Stored XSS", "vuln": "Stored XSS",
                      "severity": "High", "url": f"{target}/admin"}],
        "recon_data": {"subdomains": [f"internal.{target}"]},
        "risk_score": 87,
    }
    data_file.parent.mkdir(parents=True, exist_ok=True)
    data_file.write_text(json.dumps([session]))


class TestSessionListIsolation:
    def test_attacker_cannot_see_victims_session_in_list(self, isolated_sessions):
        _seed_session(isolated_sessions, "ART-VICTIM-1", user_id=999, target="victim-internal.example.com")

        async def go():
            return await art_router.list_sessions(user=_fake_user(1))
        result = _run(go())
        session_ids = [s["id"] for s in result["sessions"]]
        assert "ART-VICTIM-1" not in session_ids, (
            "IDOR: attacker's session list includes another user's red-team session"
        )

    def test_owner_sees_own_session_in_list(self, isolated_sessions):
        _seed_session(isolated_sessions, "ART-OWNER-1", user_id=1, target="mine.example.com")

        async def go():
            return await art_router.list_sessions(user=_fake_user(1))
        result = _run(go())
        session_ids = [s["id"] for s in result["sessions"]]
        assert "ART-OWNER-1" in session_ids


class TestSessionGetOwnership:
    def test_attacker_cannot_fetch_victims_session_by_id(self, isolated_sessions):
        _seed_session(isolated_sessions, "ART-VICTIM-2", user_id=999, target="victim-internal.example.com")

        async def go():
            return await art_router.get_session(session_id="ART-VICTIM-2", user=_fake_user(1))
        with pytest.raises(HTTPException) as exc_info:
            _run(go())
        assert exc_info.value.status_code == 404, (
            f"IDOR: attacker fetched another user's session (got {exc_info.value.status_code})"
        )

    def test_owner_can_fetch_own_session(self, isolated_sessions):
        _seed_session(isolated_sessions, "ART-OWNER-2", user_id=1, target="mine.example.com")

        async def go():
            return await art_router.get_session(session_id="ART-OWNER-2", user=_fake_user(1))
        result = _run(go())
        assert result["id"] == "ART-OWNER-2"

    def test_admin_can_fetch_any_session(self, isolated_sessions):
        _seed_session(isolated_sessions, "ART-VICTIM-3", user_id=999, target="victim-internal.example.com")

        async def go():
            return await art_router.get_session(session_id="ART-VICTIM-3", user=_fake_user(2, role="admin"))
        result = _run(go())
        assert result["id"] == "ART-VICTIM-3"


class TestGenerateReportOwnership:
    def test_attacker_cannot_generate_report_from_victims_session(self, isolated_sessions):
        _seed_session(isolated_sessions, "ART-VICTIM-4", user_id=999, target="victim-internal.example.com")

        async def go():
            return await art_router.generate_report(session_id="ART-VICTIM-4", user=_fake_user(1))
        with pytest.raises(HTTPException) as exc_info:
            _run(go())
        assert exc_info.value.status_code == 404, (
            f"IDOR: attacker generated a pentest report from another user's session "
            f"(got {exc_info.value.status_code})"
        )

    def test_owner_can_generate_report_from_own_session(self, isolated_sessions):
        _seed_session(isolated_sessions, "ART-OWNER-4", user_id=1, target="mine.example.com")

        async def go():
            return await art_router.generate_report(session_id="ART-OWNER-4", user=_fake_user(1))
        result = _run(go())
        assert result is not None
