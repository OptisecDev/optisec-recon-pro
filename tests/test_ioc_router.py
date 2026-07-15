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
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from web.database import Base
from web.models import User, Ioc, Scan, Finding
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


class TestSearchIocsEndpoint:
    def test_finds_substring_match(self, db_factory):
        async def go():
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("domain", "evil-phish.com", source="manual")
                await repo.create("domain", "safe.com", source="manual")
                await db.commit()
                return await ioc_router.search_iocs(q="phish", user=_fake_user(), db=db)
        data = _body(_run(go()))
        assert data["count"] == 1
        assert data["iocs"][0]["ioc_value"] == "evil-phish.com"

    def test_rejects_empty_query(self, db_factory):
        async def go():
            async with db_factory() as db:
                return await ioc_router.search_iocs(q="   ", user=_fake_user(), db=db)
        resp = _run(go())
        assert resp.status_code == 400

    def test_rejects_unsupported_ioc_type(self, db_factory):
        async def go():
            async with db_factory() as db:
                return await ioc_router.search_iocs(q="x", ioc_type="cidr", user=_fake_user(), db=db)
        resp = _run(go())
        assert resp.status_code == 400

    def test_no_match_returns_empty_list(self, db_factory):
        async def go():
            async with db_factory() as db:
                return await ioc_router.search_iocs(q="nope", user=_fake_user(), db=db)
        data = _body(_run(go()))
        assert data == {"iocs": [], "count": 0}


class TestSyncIocsEndpoint:
    def test_no_api_key_configured_is_a_safe_no_op(self, db_factory, monkeypatch):
        import config
        monkeypatch.setattr(config, "OTX_API_KEY", "")

        async def go():
            async with db_factory() as db:
                return await ioc_router.sync_iocs(user=_fake_user(), db=db)
        data = _body(_run(go()))
        assert data == {"fetched": 0, "stored": 0, "skipped": 0}

    def test_stores_fetched_indicators_and_commits(self, db_factory, monkeypatch):
        def fake_client(limit):
            return [{"type": "ip", "value": "8.8.8.8", "threat_score": 77}]
        monkeypatch.setattr("modules.ioc.ioc_engine._default_otx_pulses_client", fake_client)

        async def go():
            async with db_factory() as db:
                resp = await ioc_router.sync_iocs(user=_fake_user(), db=db)
                repo = IOCRepository(db)
                row = await repo.get_by_value("ip", "8.8.8.8")
                return resp, row
        resp, row = _run(go())
        data = _body(resp)
        assert data == {"fetched": 1, "stored": 1, "skipped": 0}
        assert row is not None
        assert row.source == "otx"
        assert row.confidence_score == 77.0

    def test_passes_limit_query_param_through(self, db_factory, monkeypatch):
        calls = []

        def fake_client(limit):
            calls.append(limit)
            return []
        monkeypatch.setattr("modules.ioc.ioc_engine._default_otx_pulses_client", fake_client)

        async def go():
            async with db_factory() as db:
                return await ioc_router.sync_iocs(limit=17, user=_fake_user(), db=db)
        _run(go())
        assert calls == [17]


class TestSyncIocsUrlhausEndpoint:
    def test_no_api_key_configured_is_a_safe_no_op(self, db_factory, monkeypatch):
        import config
        monkeypatch.setattr(config, "URLHAUS_API_KEY", "")

        async def go():
            async with db_factory() as db:
                return await ioc_router.sync_iocs_urlhaus(user=_fake_user(), db=db)
        data = _body(_run(go()))
        assert data == {"fetched": 0, "stored": 0, "skipped": 0}

    def test_stores_fetched_indicators_and_commits(self, db_factory, monkeypatch):
        def fake_client(limit):
            return [{"type": "url", "value": "http://evil.com/x", "threat_score": 91}]
        monkeypatch.setattr("modules.ioc.ioc_engine._default_urlhaus_recent_client", fake_client)

        async def go():
            async with db_factory() as db:
                resp = await ioc_router.sync_iocs_urlhaus(user=_fake_user(), db=db)
                repo = IOCRepository(db)
                row = await repo.get_by_value("url", "http://evil.com/x")
                return resp, row
        resp, row = _run(go())
        data = _body(resp)
        assert data == {"fetched": 1, "stored": 1, "skipped": 0}
        assert row is not None
        assert row.source == "urlhaus"
        assert row.confidence_score == 91.0

    def test_passes_limit_query_param_through(self, db_factory, monkeypatch):
        calls = []

        def fake_client(limit):
            calls.append(limit)
            return []
        monkeypatch.setattr("modules.ioc.ioc_engine._default_urlhaus_recent_client", fake_client)

        async def go():
            async with db_factory() as db:
                return await ioc_router.sync_iocs_urlhaus(limit=17, user=_fake_user(), db=db)
        _run(go())
        assert calls == [17]


class TestScanIocMatchesEndpoint:
    async def _seed_scan_with_findings(self, session_factory, owner_id: int) -> str:
        async with session_factory() as db:
            scan = Scan(id="scan-1", user_id=owner_id, target_url="https://myapp.example")
            db.add(scan)
            await db.flush()
            db.add(Finding(
                scan_id=scan.id, vuln_type="SSRF",
                url="https://myapp.example/fetch?url=x",
                evidence="Outbound connection observed to 8.8.8.8 before timeout",
            ))
            await db.commit()
        return "scan-1"

    def test_returns_matches_for_known_iocs(self, db_factory):
        async def go():
            scan_id = await self._seed_scan_with_findings(db_factory, owner_id=1)
            async with db_factory() as db:
                repo = IOCRepository(db)
                await repo.create("ip", "8.8.8.8", source="otx", confidence_score=90.0)
                await db.commit()
                return await ioc_router.scan_ioc_matches(scan_id, user=_fake_user(), db=db)
        data = _body(_run(go()))
        assert data["scan_id"] == "scan-1"
        assert data["count"] == 1
        assert data["matches"][0]["ioc_value"] == "8.8.8.8"

    def test_no_matches_for_unknown_infrastructure(self, db_factory):
        async def go():
            scan_id = await self._seed_scan_with_findings(db_factory, owner_id=1)
            async with db_factory() as db:
                return await ioc_router.scan_ioc_matches(scan_id, user=_fake_user(), db=db)
        data = _body(_run(go()))
        assert data == {"scan_id": "scan-1", "matches": [], "count": 0}

    def test_missing_scan_returns_404(self, db_factory):
        async def go():
            async with db_factory() as db:
                return await ioc_router.scan_ioc_matches("no-such-scan", user=_fake_user(), db=db)
        with pytest.raises(HTTPException) as exc_info:
            _run(go())
        assert exc_info.value.status_code == 404

    def test_other_users_scan_returns_403(self, db_factory):
        async def go():
            scan_id = await self._seed_scan_with_findings(db_factory, owner_id=999)
            async with db_factory() as db:
                return await ioc_router.scan_ioc_matches(scan_id, user=_fake_user(), db=db)
        with pytest.raises(HTTPException) as exc_info:
            _run(go())
        assert exc_info.value.status_code == 403

    def test_admin_can_view_any_users_scan(self, db_factory):
        admin = User(id=2, username="admin", email="admin@example.com", password_hash="x", role="admin")

        async def go():
            scan_id = await self._seed_scan_with_findings(db_factory, owner_id=999)
            async with db_factory() as db:
                return await ioc_router.scan_ioc_matches(scan_id, user=admin, db=db)
        data = _body(_run(go()))
        assert data["scan_id"] == "scan-1"


class TestSchedulerStatusEndpoint:
    """Mirrors web/routers/darkweb_monitor.py::scheduler_status — no role
    restriction (any authenticated user), just JSONResponse(get_status())."""

    def test_matches_get_status_shape_and_default_not_running(self):
        import modules.ioc.scheduler as ioc_sched
        ioc_sched.stop_scheduler()  # ensure a clean not-running baseline

        data = _body(_run(ioc_router.scheduler_status(user=_fake_user())))

        assert set(data.keys()) == {
            "running", "interval_hours", "worker_id",
            "last_run_at", "last_run_summary", "next_run_at",
        }
        assert data["running"] is False
        assert data == ioc_sched.get_status()

    def test_reflects_running_state(self, monkeypatch):
        import modules.ioc.scheduler as ioc_sched
        monkeypatch.setenv("IOC_OTX_SYNC_INTERVAL_HOURS", "9")
        ioc_sched.start_scheduler(asyncio.new_event_loop())
        try:
            data = _body(_run(ioc_router.scheduler_status(user=_fake_user())))
            assert data["running"] is True
            assert data["interval_hours"] == 9.0
            assert data["next_run_at"] is not None
        finally:
            ioc_sched.stop_scheduler()


class TestSchedulerStatusUrlhausEndpoint:
    """Mirrors TestSchedulerStatusEndpoint for the URLhaus job's status
    endpoint — same shape, independent job/interval/run-history."""

    def test_matches_get_urlhaus_status_shape_and_default_not_running(self):
        import modules.ioc.scheduler as ioc_sched
        ioc_sched.stop_scheduler()  # ensure a clean not-running baseline

        data = _body(_run(ioc_router.scheduler_status_urlhaus(user=_fake_user())))

        assert set(data.keys()) == {
            "running", "interval_hours", "worker_id",
            "last_run_at", "last_run_summary", "next_run_at",
        }
        assert data["running"] is False
        assert data == ioc_sched.get_urlhaus_status()

    def test_reflects_running_state(self, monkeypatch):
        import modules.ioc.scheduler as ioc_sched
        monkeypatch.setenv("IOC_URLHAUS_SYNC_INTERVAL_HOURS", "7")
        ioc_sched.start_scheduler(asyncio.new_event_loop())
        try:
            data = _body(_run(ioc_router.scheduler_status_urlhaus(user=_fake_user())))
            assert data["running"] is True
            assert data["interval_hours"] == 7.0
            assert data["next_run_at"] is not None
        finally:
            ioc_sched.stop_scheduler()
