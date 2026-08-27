"""Tests for web/routers/autonomous_rt.py's target ownership gate.

Mirrors tests/test_ioc_router.py's convention: plain pytest, async functions
driven via asyncio.run(), an in-memory SQLite engine (no mocking of the DB
layer itself), and calling the route handler functions directly (bypassing
FastAPI's Depends resolution by passing already-built user/db values).

Before this gate existed, /autonomous-redteam/api/start accepted any
free-text `target` string plus a decorative `scope: List[str]` that was
never validated. These tests cover check_target_ownership() and the
/api/start handler that now requires a target_id referring to a Target row
owned by the authenticated user.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from web.database import Base
from web.models import User, Target
import web.routers.autonomous_rt as art_router
import web.license as license_module


def _run(coro):
    return asyncio.run(coro)


def _enterprise_license() -> license_module.License:
    """autonomous_redteam is enterprise-only; these tests are about target
    ownership, not licensing, so give every test an always-entitled license."""
    return license_module.License(
        tier="enterprise", issued_to="test", email="",
        issued_at="2026-01-01T00:00:00", expires_at="2099-01-01T00:00:00", key="TEST",
        features=license_module.TIER_FEATURES["enterprise"],
        max_targets=-1, max_scans_day=-1, max_users=-1,
    )


@pytest.fixture(autouse=True)
def _enterprise_tier(monkeypatch):
    monkeypatch.setattr(license_module, "get_license", _enterprise_license)


@pytest.fixture
def db_factory():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    _run(_setup())
    yield session_factory
    _run(engine.dispose())


def _fake_user(user_id: int = 1) -> User:
    return User(id=user_id, username=f"analyst{user_id}", email=f"a{user_id}@example.com",
                password_hash="x", role="analyst")


class _FakeRequest:
    def __init__(self, body: dict):
        self._body = body

    async def json(self):
        return self._body


async def _create_target(session_factory, owner_id: int, url: str = "https://target.example.com") -> int:
    async with session_factory() as db:
        target = Target(user_id=owner_id, url=url, name="Test Target")
        db.add(target)
        await db.commit()
        await db.refresh(target)
        return target.id


class TestCheckTargetOwnership:
    def test_unregistered_target_is_rejected(self, db_factory):
        async def go():
            async with db_factory() as db:
                return await art_router.check_target_ownership(9999, _fake_user(1), db)
        with pytest.raises(HTTPException) as exc_info:
            _run(go())
        assert exc_info.value.status_code == 404

    def test_target_owned_by_another_user_is_rejected(self, db_factory):
        async def go():
            target_id = await _create_target(db_factory, owner_id=999)
            async with db_factory() as db:
                return await art_router.check_target_ownership(target_id, _fake_user(1), db)
        with pytest.raises(HTTPException) as exc_info:
            _run(go())
        assert exc_info.value.status_code == 404

    def test_target_owned_by_same_user_succeeds(self, db_factory):
        async def go():
            target_id = await _create_target(db_factory, owner_id=1, url="https://mine.example.com")
            async with db_factory() as db:
                return await art_router.check_target_ownership(target_id, _fake_user(1), db)
        target = _run(go())
        assert target.url == "https://mine.example.com"


class TestStartSimulationEndpoint:
    @pytest.fixture(autouse=True)
    def _isolate_sessions_file(self, tmp_path, monkeypatch):
        import modules.ai_advanced.autonomous_redteam as art
        monkeypatch.setattr(art, "DATA_FILE", tmp_path / "autonomous_rt_sessions.json")
        monkeypatch.delenv("GROQ_API_KEY", raising=False)

    def test_unregistered_target_id_returns_404(self, db_factory):
        async def go():
            async with db_factory() as db:
                return await art_router.start_simulation(
                    _FakeRequest({"target_id": 4242, "attack_types": ["xss"]}),
                    user=_fake_user(1), db=db,
                )
        with pytest.raises(HTTPException) as exc_info:
            _run(go())
        assert exc_info.value.status_code == 404

    def test_other_users_target_id_returns_404(self, db_factory):
        async def go():
            target_id = await _create_target(db_factory, owner_id=999)
            async with db_factory() as db:
                return await art_router.start_simulation(
                    _FakeRequest({"target_id": target_id, "attack_types": ["xss"]}),
                    user=_fake_user(1), db=db,
                )
        with pytest.raises(HTTPException) as exc_info:
            _run(go())
        assert exc_info.value.status_code == 404

    def test_own_target_id_starts_simulation(self, db_factory):
        async def go():
            target_id = await _create_target(db_factory, owner_id=1, url="https://mine.example.com")
            async with db_factory() as db:
                return await art_router.start_simulation(
                    _FakeRequest({"target_id": target_id, "attack_types": ["xss"]}),
                    user=_fake_user(1), db=db,
                )
        session = _run(go())
        assert session["target"] == "https://mine.example.com"
        assert session["status"] == "completed"
        assert "scope" not in session
