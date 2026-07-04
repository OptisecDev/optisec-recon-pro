"""Tests for web/routers/ioc.py — GET /api/iocs.

Mirrors tests/test_honeypot.py's convention: plain pytest, async functions
driven via asyncio.run(), an in-memory SQLite engine (no mocking of the DB
layer itself), and calling the route handler function directly (bypassing
FastAPI's Depends resolution by passing already-built user/db values) since
that's all the router logic amounts to on top of already-tested
IOCRepository — no HTTP layer needed to exercise it.
"""

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from web.database import Base
from web.models import User, Ioc
import web.routers.ioc as ioc_router
from modules.ioc.ioc_engine import IOCRepository


def _run(coro):
    return asyncio.run(coro)


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


def _fake_user() -> User:
    return User(id=1, username="analyst", email="a@example.com", password_hash="x", role="analyst")


def _body(response) -> dict:
    return json.loads(response.body)


class TestIocToDict:
    def test_shape_and_iso_timestamps(self):
        row = Ioc(
            id=1, ioc_type="ip", ioc_value="1.2.3.4", source="scan_finding",
            confidence_score=42.0, related_finding_id=7, tags=["vuln_type:SSRF"],
            is_active=True,
        )
        d = ioc_router._ioc_to_dict(row)
        assert d == {
            "id": 1, "ioc_type": "ip", "ioc_value": "1.2.3.4", "source": "scan_finding",
            "confidence_score": 42.0, "first_seen": None, "last_seen": None,
            "related_finding_id": 7, "tags": ["vuln_type:SSRF"], "is_active": True,
        }


class TestListIocsEndpoint:
    def test_lists_all_by_default(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("ip", "1.1.1.1", source="manual")
                await repo.create("domain", "evil.com", source="manual")
                await db.commit()
                return await ioc_router.list_iocs(user=_fake_user(), db=db)
        resp = _run(go())
        data = _body(resp)
        assert data["count"] == 2
        assert {i["ioc_value"] for i in data["iocs"]} == {"1.1.1.1", "evil.com"}

    def test_filters_by_ioc_type(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("ip", "1.1.1.1", source="manual")
                await repo.create("domain", "evil.com", source="manual")
                await db.commit()
                return await ioc_router.list_iocs(ioc_type="domain", user=_fake_user(), db=db)
        data = _body(_run(go()))
        assert data["count"] == 1
        assert data["iocs"][0]["ioc_value"] == "evil.com"

    def test_filters_by_is_active(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("ip", "1.1.1.1", source="manual", is_active=True)
                await repo.create("ip", "2.2.2.2", source="manual", is_active=False)
                await db.commit()
                return await ioc_router.list_iocs(is_active=False, user=_fake_user(), db=db)
        data = _body(_run(go()))
        assert data["count"] == 1
        assert data["iocs"][0]["ioc_value"] == "2.2.2.2"

    def test_pagination(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                for i in range(5):
                    await repo.create("ip", f"1.1.1.{i}", source="manual")
                await db.commit()
                return await ioc_router.list_iocs(limit=2, offset=1, user=_fake_user(), db=db)
        data = _body(_run(go()))
        assert data["count"] == 2
        assert data["limit"] == 2
        assert data["offset"] == 1

    def test_rejects_unsupported_ioc_type(self, db_factory):
        async def go():
            async with db_factory() as db:
                return await ioc_router.list_iocs(ioc_type="cidr", user=_fake_user(), db=db)
        resp = _run(go())
        assert resp.status_code == 400
        assert "cidr" in _body(resp)["error"]
