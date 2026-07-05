"""
Tests for the IOC OTX periodic sync scheduler (modules/ioc/scheduler.py).

Mirrors tests/test_darkweb_scheduler.py's conventions: plain pytest, async
functions driven via asyncio.run(), monkeypatch for isolation. No real
network calls and no shared state with the project's real database — every
test gets its own in-memory SQLite engine wired in place of
web.database.SessionLocal.
"""

import asyncio
import os
import sys
import threading
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

import web.database as database
from web.database import Base
from web.models import Ioc, SchedulerLock  # noqa: F401 — Ioc import registers the table on Base.metadata
import modules.ioc.scheduler as sched


def _run(coro):
    return asyncio.run(coro)


# ── Isolated in-memory DB fixture ────────────────────────────────────────────

@pytest.fixture
def db(monkeypatch):
    """An in-memory SQLite engine, wired in place of web.database.SessionLocal
    so scheduler code (which does `from web import database as _db` and calls
    `_db.SessionLocal()`) transparently uses it."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    TestSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    _run(_setup())
    monkeypatch.setattr(database, "SessionLocal", TestSessionLocal)
    yield TestSessionLocal
    _run(engine.dispose())


@pytest.fixture(autouse=True)
def _reset_scheduler_state():
    """Every test starts and ends with no live BackgroundScheduler and no
    stale module-level run history, so tests can't leak into each other."""
    sched.stop_scheduler()
    sched._last_run_at = None
    sched._last_run_summary = None
    yield
    sched.stop_scheduler()
    sched._last_run_at = None
    sched._last_run_summary = None


def _patch_sync(monkeypatch, result: dict):
    """Stub out IOCEngine.sync_from_otx so no network I/O happens."""
    async def fake_sync(self, limit=100):
        return result
    monkeypatch.setattr("modules.ioc.ioc_engine.IOCEngine.sync_from_otx", fake_sync)


# ── 1. Interval / limit configuration (mocked "timing") ─────────────────────

class TestIntervalConfig:
    def test_default_is_6_hours(self, monkeypatch):
        monkeypatch.delenv("IOC_OTX_SYNC_INTERVAL_HOURS", raising=False)
        assert sched.get_sync_interval_hours() == 6.0

    def test_reads_custom_env_value(self, monkeypatch):
        monkeypatch.setenv("IOC_OTX_SYNC_INTERVAL_HOURS", "3")
        assert sched.get_sync_interval_hours() == 3.0

    def test_invalid_value_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("IOC_OTX_SYNC_INTERVAL_HOURS", "not-a-number")
        assert sched.get_sync_interval_hours() == 6.0

    def test_non_positive_value_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("IOC_OTX_SYNC_INTERVAL_HOURS", "0")
        assert sched.get_sync_interval_hours() == 6.0
        monkeypatch.setenv("IOC_OTX_SYNC_INTERVAL_HOURS", "-5")
        assert sched.get_sync_interval_hours() == 6.0


class TestSyncLimitConfig:
    def test_default_is_100(self, monkeypatch):
        monkeypatch.delenv("IOC_OTX_SYNC_LIMIT", raising=False)
        assert sched.get_sync_limit() == 100

    def test_reads_custom_env_value(self, monkeypatch):
        monkeypatch.setenv("IOC_OTX_SYNC_LIMIT", "25")
        assert sched.get_sync_limit() == 25

    def test_invalid_value_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("IOC_OTX_SYNC_LIMIT", "not-a-number")
        assert sched.get_sync_limit() == 100

    def test_non_positive_value_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("IOC_OTX_SYNC_LIMIT", "0")
        assert sched.get_sync_limit() == 100


# ── 2. DB-backed lock (no duplicate runs across workers) ─────────────────────

class TestLock:
    def test_acquire_succeeds_when_free(self, db):
        async def go():
            async with db() as db_:
                assert await sched._acquire_lock(db_, "job", "worker-a", timedelta(hours=2)) is True
        _run(go())

    def test_second_worker_blocked_while_held(self, db):
        async def go():
            async with db() as db_:
                assert await sched._acquire_lock(db_, "job", "worker-a", timedelta(hours=2)) is True
            async with db() as db_:
                assert await sched._acquire_lock(db_, "job", "worker-b", timedelta(hours=2)) is False
        _run(go())

    def test_stale_lock_is_reclaimed(self, db):
        async def go():
            async with db() as db_:
                db_.add(SchedulerLock(job_name="job", locked_at=datetime.utcnow() - timedelta(hours=5),
                                       locked_by="dead-worker"))
                await db_.commit()
            async with db() as db_:
                assert await sched._acquire_lock(db_, "job", "worker-b", timedelta(hours=2)) is True
        _run(go())

    def test_release_by_non_holder_is_ignored(self, db):
        async def go():
            async with db() as db_:
                assert await sched._acquire_lock(db_, "job", "worker-a", timedelta(hours=2)) is True
            async with db() as db_:
                await sched._release_lock(db_, "job", "worker-b")  # not the holder
            async with db() as db_:
                assert await sched._acquire_lock(db_, "job", "worker-c", timedelta(hours=2)) is False
        _run(go())

    def test_release_by_holder_frees_the_lock(self, db):
        async def go():
            async with db() as db_:
                assert await sched._acquire_lock(db_, "job", "worker-a", timedelta(hours=2)) is True
            async with db() as db_:
                await sched._release_lock(db_, "job", "worker-a")
            async with db() as db_:
                assert await sched._acquire_lock(db_, "job", "worker-d", timedelta(hours=2)) is True
        _run(go())


# ── 3. run_scheduled_sync — lock + delegation to IOCEngine.sync_from_otx ─────

class TestRunScheduledSync:
    def test_runs_sync_and_stores_summary(self, db, monkeypatch):
        _patch_sync(monkeypatch, {"fetched": 5, "stored": 3, "skipped": 2})
        summary = _run(sched.run_scheduled_sync())
        assert summary == {"fetched": 5, "stored": 3, "skipped": 2}

    def test_lock_prevents_duplicate_sweep(self, db, monkeypatch):
        """Simulates a second worker/instance firing the same job while the
        first already holds the lock — it must skip entirely, never calling
        sync_from_otx."""
        called = {"flag": False}

        async def fake_sync(self, limit=100):
            called["flag"] = True
            return {"fetched": 0, "stored": 0, "skipped": 0}
        monkeypatch.setattr("modules.ioc.ioc_engine.IOCEngine.sync_from_otx", fake_sync)

        async def seed_lock():
            async with db() as db_:
                db_.add(SchedulerLock(job_name=sched.LOCK_NAME, locked_at=datetime.utcnow(),
                                       locked_by="other-worker-already-running"))
                await db_.commit()
        _run(seed_lock())

        summary = _run(sched.run_scheduled_sync())
        assert called["flag"] is False
        assert summary == {"skipped": True, "reason": "lock_held"}

    def test_lock_is_released_after_the_sync_so_the_next_run_can_proceed(self, db, monkeypatch):
        _patch_sync(monkeypatch, {"fetched": 1, "stored": 1, "skipped": 0})
        _run(sched.run_scheduled_sync())

        async def lock_row():
            async with db() as db_:
                return (await db_.execute(
                    select(SchedulerLock).where(SchedulerLock.job_name == sched.LOCK_NAME)
                )).scalar_one()
        row = _run(lock_row())
        assert row.locked_at is None
        assert row.locked_by is None

    def test_lock_is_released_even_if_sync_raises(self, db, monkeypatch):
        async def boom(self, limit=100):
            raise RuntimeError("OTX API exploded")
        monkeypatch.setattr("modules.ioc.ioc_engine.IOCEngine.sync_from_otx", boom)

        summary = _run(sched.run_scheduled_sync())
        assert summary["error"] == "sync_failed"

        async def lock_row():
            async with db() as db_:
                return (await db_.execute(
                    select(SchedulerLock).where(SchedulerLock.job_name == sched.LOCK_NAME)
                )).scalar_one()
        row = _run(lock_row())
        assert row.locked_at is None

    def test_end_to_end_with_real_engine_and_no_api_key_is_a_safe_no_op(self, db, monkeypatch):
        """No stubbing of IOCEngine itself — exercises the real
        sync_from_otx() -> _default_otx_pulses_client() path with no
        OTX_API_KEY configured, verifying the scheduler surfaces its
        all-zero summary rather than erroring."""
        import config
        monkeypatch.setattr(config, "OTX_API_KEY", "")

        summary = _run(sched.run_scheduled_sync())
        assert summary == {"fetched": 0, "stored": 0, "skipped": 0}

    def test_end_to_end_persists_real_indicators_via_real_engine(self, db, monkeypatch):
        monkeypatch.setattr(
            "modules.ioc.ioc_engine._default_otx_pulses_client",
            lambda limit: [{"type": "domain", "value": "evil.com", "threat_score": 88}],
        )

        summary = _run(sched.run_scheduled_sync())
        assert summary == {"fetched": 1, "stored": 1, "skipped": 0}

        async def stored():
            async with db() as db_:
                return (await db_.execute(select(Ioc).where(Ioc.ioc_value == "evil.com"))).scalar_one_or_none()
        row = _run(stored())
        assert row is not None
        assert row.source == "otx"


# ── 4. _run_sync_job — the sync APScheduler entrypoint never raises ─────────

class TestRunSyncJob:
    def test_never_raises_even_if_the_sync_crashes(self, monkeypatch):
        """_run_sync_job submits to sched._app_loop via run_coroutine_threadsafe
        (see modules/ioc/scheduler.py's module docstring for why: reusing
        asyncio.run()'s brand-new loop per firing corrupts the shared asyncpg
        pool). Mirror that topology here — a loop running on its own thread
        stands in for the app's event loop, while this test thread plays the
        part of APScheduler's own thread firing the job."""
        async def boom():
            raise RuntimeError("db is unreachable")
        monkeypatch.setattr(sched, "run_scheduled_sync", boom)

        loop = asyncio.new_event_loop()
        thread = threading.Thread(target=loop.run_forever, daemon=True)
        thread.start()
        sched._app_loop = loop
        try:
            sched._run_sync_job()  # must not raise
        finally:
            loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=2)
            loop.close()


# ── 5. Lifecycle — start/stop/status ─────────────────────────────────────────

class TestLifecycle:
    def test_start_scheduler_runs_and_configures_interval(self, monkeypatch):
        monkeypatch.setenv("IOC_OTX_SYNC_INTERVAL_HOURS", "3")
        scheduler = sched.start_scheduler(asyncio.new_event_loop())
        try:
            assert scheduler.running is True
            job = scheduler.get_job(sched.JOB_ID)
            assert job is not None
            assert job.trigger.interval == timedelta(hours=3)
        finally:
            sched.stop_scheduler()

    def test_start_is_idempotent(self, monkeypatch):
        monkeypatch.setenv("IOC_OTX_SYNC_INTERVAL_HOURS", "6")
        s1 = sched.start_scheduler(asyncio.new_event_loop())
        s2 = sched.start_scheduler(asyncio.new_event_loop())
        assert s1 is s2
        sched.stop_scheduler()

    def test_stop_before_start_is_safe(self):
        sched.stop_scheduler()  # no-op, must not raise

    def test_get_status_reflects_running_state(self, monkeypatch):
        monkeypatch.setenv("IOC_OTX_SYNC_INTERVAL_HOURS", "12")
        assert sched.get_status()["running"] is False

        sched.start_scheduler(asyncio.new_event_loop())
        status = sched.get_status()
        assert status["running"] is True
        assert status["interval_hours"] == 12.0
        assert status["next_run_at"] is not None

        sched.stop_scheduler()
        assert sched.get_status()["running"] is False

    def test_get_status_reports_last_run_summary(self, db, monkeypatch):
        _patch_sync(monkeypatch, {"fetched": 2, "stored": 2, "skipped": 0})
        _run(sched.run_scheduled_sync())
        status = sched.get_status()
        assert status["last_run_at"] is not None
        assert status["last_run_summary"] == {"fetched": 2, "stored": 2, "skipped": 0}
