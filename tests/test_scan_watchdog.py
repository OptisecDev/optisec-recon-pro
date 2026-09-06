"""
Tests for the Scan Watchdog periodic scheduler
(modules/scan_watchdog/scheduler.py).

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
from web.models import User, Scan, SchedulerLock
import modules.scan_watchdog.scheduler as sched


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


async def _seed_user(session_factory) -> int:
    async with session_factory() as db_:
        user = User(username="u1", email="u1@example.com", password_hash="x",
                    role="analyst", api_key_hash="k1", is_active=True)
        db_.add(user)
        await db_.commit()
        await db_.refresh(user)
        return user.id


async def _seed_scan(session_factory, user_id: int, scan_id: str, *, status: str,
                      started_at=None, created_at=None) -> str:
    async with session_factory() as db_:
        s = Scan(
            id=scan_id, user_id=user_id, target_url="http://example.com",
            scan_types=["nmap"], status=status, progress=0,
            created_at=created_at or datetime.utcnow(), started_at=started_at,
        )
        db_.add(s)
        await db_.commit()
        return s.id


# ── 1. Interval / threshold configuration ────────────────────────────────────

class TestIntervalConfig:
    def test_default_sweep_interval_is_30_minutes(self, monkeypatch):
        monkeypatch.delenv("SCAN_WATCHDOG_SWEEP_INTERVAL_MINUTES", raising=False)
        assert sched.get_sweep_interval_minutes() == 30.0

    def test_reads_custom_sweep_interval(self, monkeypatch):
        monkeypatch.setenv("SCAN_WATCHDOG_SWEEP_INTERVAL_MINUTES", "10")
        assert sched.get_sweep_interval_minutes() == 10.0

    def test_invalid_sweep_interval_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("SCAN_WATCHDOG_SWEEP_INTERVAL_MINUTES", "not-a-number")
        assert sched.get_sweep_interval_minutes() == 30.0

    def test_non_positive_sweep_interval_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("SCAN_WATCHDOG_SWEEP_INTERVAL_MINUTES", "0")
        assert sched.get_sweep_interval_minutes() == 30.0
        monkeypatch.setenv("SCAN_WATCHDOG_SWEEP_INTERVAL_MINUTES", "-5")
        assert sched.get_sweep_interval_minutes() == 30.0

    def test_default_stale_timeout_is_2_hours(self, monkeypatch):
        monkeypatch.delenv("SCAN_WATCHDOG_STALE_TIMEOUT_HOURS", raising=False)
        assert sched.get_stale_timeout_hours() == 2.0

    def test_reads_custom_stale_timeout(self, monkeypatch):
        monkeypatch.setenv("SCAN_WATCHDOG_STALE_TIMEOUT_HOURS", "4")
        assert sched.get_stale_timeout_hours() == 4.0

    def test_invalid_stale_timeout_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("SCAN_WATCHDOG_STALE_TIMEOUT_HOURS", "nope")
        assert sched.get_stale_timeout_hours() == 2.0

    def test_non_positive_stale_timeout_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("SCAN_WATCHDOG_STALE_TIMEOUT_HOURS", "0")
        assert sched.get_stale_timeout_hours() == 2.0


# ── 2. DB-backed lock (no duplicate runs across workers) ─────────────────────

class TestLock:
    def test_acquire_succeeds_when_free(self, db):
        async def go():
            async with db() as db_:
                assert await sched._acquire_lock(db_, "job", "worker-a", timedelta(hours=1)) is True
        _run(go())

    def test_second_worker_blocked_while_held(self, db):
        async def go():
            async with db() as db_:
                assert await sched._acquire_lock(db_, "job", "worker-a", timedelta(hours=1)) is True
            async with db() as db_:
                assert await sched._acquire_lock(db_, "job", "worker-b", timedelta(hours=1)) is False
        _run(go())

    def test_stale_lock_is_reclaimed(self, db):
        async def go():
            async with db() as db_:
                db_.add(SchedulerLock(job_name="job", locked_at=datetime.utcnow() - timedelta(hours=5),
                                       locked_by="dead-worker"))
                await db_.commit()
            async with db() as db_:
                assert await sched._acquire_lock(db_, "job", "worker-b", timedelta(hours=1)) is True
        _run(go())

    def test_release_by_non_holder_is_ignored(self, db):
        async def go():
            async with db() as db_:
                assert await sched._acquire_lock(db_, "job", "worker-a", timedelta(hours=1)) is True
            async with db() as db_:
                await sched._release_lock(db_, "job", "worker-b")  # not the holder
            async with db() as db_:
                assert await sched._acquire_lock(db_, "job", "worker-c", timedelta(hours=1)) is False
        _run(go())

    def test_release_by_holder_frees_the_lock(self, db):
        async def go():
            async with db() as db_:
                assert await sched._acquire_lock(db_, "job", "worker-a", timedelta(hours=1)) is True
            async with db() as db_:
                await sched._release_lock(db_, "job", "worker-a")
            async with db() as db_:
                assert await sched._acquire_lock(db_, "job", "worker-d", timedelta(hours=1)) is True
        _run(go())


# ── 3. run_scan_watchdog_sweep — which scans get reaped ──────────────────────

class TestRunSweep:
    def test_reaps_stale_running_and_pending_but_not_fresh_or_terminal(self, db, monkeypatch):
        monkeypatch.setenv("SCAN_WATCHDOG_STALE_TIMEOUT_HOURS", "2")
        long_ago = datetime.utcnow() - timedelta(hours=5)
        recent = datetime.utcnow()

        async def seed():
            uid = await _seed_user(db)
            await _seed_scan(db, uid, "fresh-running", status="running", started_at=recent)
            await _seed_scan(db, uid, "stale-running", status="running", started_at=long_ago)
            await _seed_scan(db, uid, "stale-pending", status="pending", started_at=long_ago)
            await _seed_scan(db, uid, "stale-done", status="done", started_at=long_ago)
            await _seed_scan(db, uid, "stale-failed", status="failed", started_at=long_ago)
        _run(seed())

        summary = _run(sched.run_scan_watchdog_sweep())
        assert sorted(summary["reaped_scan_ids"]) == ["stale-pending", "stale-running"]
        assert summary["reaped"] == 2

        async def statuses():
            async with db() as db_:
                rows = (await db_.execute(select(Scan))).scalars().all()
                return {r.id: r.status for r in rows}
        result = _run(statuses())
        assert result["fresh-running"] == "running"
        assert result["stale-running"] == "failed"
        assert result["stale-pending"] == "failed"
        assert result["stale-done"] == "done"
        assert result["stale-failed"] == "failed"

    def test_falls_back_to_created_at_when_started_at_is_null(self, db, monkeypatch):
        monkeypatch.setenv("SCAN_WATCHDOG_STALE_TIMEOUT_HOURS", "2")
        long_ago = datetime.utcnow() - timedelta(hours=5)

        async def seed():
            uid = await _seed_user(db)
            await _seed_scan(db, uid, "never-started-pending", status="pending",
                              started_at=None, created_at=long_ago)
        _run(seed())

        summary = _run(sched.run_scan_watchdog_sweep())
        assert summary["reaped_scan_ids"] == ["never-started-pending"]

    def test_sets_error_message_and_completed_at(self, db, monkeypatch):
        monkeypatch.setenv("SCAN_WATCHDOG_STALE_TIMEOUT_HOURS", "2")
        long_ago = datetime.utcnow() - timedelta(hours=5)

        async def seed():
            uid = await _seed_user(db)
            await _seed_scan(db, uid, "stale-running", status="running", started_at=long_ago)
        _run(seed())

        _run(sched.run_scan_watchdog_sweep())

        async def fetch():
            async with db() as db_:
                return await db_.get(Scan, "stale-running")
        row = _run(fetch())
        assert row.status == "failed"
        assert "watchdog" in row.error.lower()
        assert "running" in row.error
        assert row.completed_at is not None

    def test_nothing_to_reap_returns_zero(self, db, monkeypatch):
        monkeypatch.setenv("SCAN_WATCHDOG_STALE_TIMEOUT_HOURS", "2")

        async def seed():
            uid = await _seed_user(db)
            await _seed_scan(db, uid, "fresh-running", status="running", started_at=datetime.utcnow())
        _run(seed())

        summary = _run(sched.run_scan_watchdog_sweep())
        assert summary == {"reaped": 0, "reaped_scan_ids": []}

    def test_lock_prevents_duplicate_sweep(self, db, monkeypatch):
        """Simulates a second worker/instance firing the same job while the
        first already holds the lock — it must skip entirely, reaping nothing."""
        long_ago = datetime.utcnow() - timedelta(hours=5)

        async def seed():
            uid = await _seed_user(db)
            await _seed_scan(db, uid, "stale-running", status="running", started_at=long_ago)
            async with db() as db_:
                db_.add(SchedulerLock(job_name=sched.LOCK_NAME, locked_at=datetime.utcnow(),
                                       locked_by="other-worker-already-running"))
                await db_.commit()
        _run(seed())

        summary = _run(sched.run_scan_watchdog_sweep())
        assert summary == {"skipped": True, "reason": "lock_held"}

        async def fetch():
            async with db() as db_:
                return await db_.get(Scan, "stale-running")
        assert _run(fetch()).status == "running"

    def test_lock_is_released_after_the_sweep_so_the_next_run_can_proceed(self, db, monkeypatch):
        long_ago = datetime.utcnow() - timedelta(hours=5)

        async def seed():
            uid = await _seed_user(db)
            await _seed_scan(db, uid, "stale-running", status="running", started_at=long_ago)
        _run(seed())

        _run(sched.run_scan_watchdog_sweep())

        async def lock_row():
            async with db() as db_:
                return (await db_.execute(
                    select(SchedulerLock).where(SchedulerLock.job_name == sched.LOCK_NAME)
                )).scalar_one()
        row = _run(lock_row())
        assert row.locked_at is None
        assert row.locked_by is None

    def test_lock_is_released_even_if_the_db_call_raises(self, db, monkeypatch):
        def boom(*args, **kwargs):
            raise RuntimeError("db connection lost")
        monkeypatch.setattr(sched, "get_stale_timeout_hours", boom)

        async def seed():
            await _seed_user(db)
        _run(seed())

        _run(sched.run_scan_watchdog_sweep())

        async def lock_row():
            async with db() as db_:
                return (await db_.execute(
                    select(SchedulerLock).where(SchedulerLock.job_name == sched.LOCK_NAME)
                )).scalar_one()
        row = _run(lock_row())
        assert row.locked_at is None


# ── 4. _run_watchdog_job — the sync APScheduler entrypoint never raises ─────

class TestRunWatchdogJob:
    def test_never_raises_even_if_the_sweep_crashes(self, monkeypatch):
        """_run_watchdog_job submits to sched._app_loop via
        run_coroutine_threadsafe (see modules/scan_watchdog/scheduler.py's
        module docstring for why: reusing asyncio.run()'s brand-new loop per
        firing corrupts the shared asyncpg pool). Mirror that topology here —
        a loop running on its own thread stands in for the app's event loop,
        while this test thread plays the part of APScheduler's own thread
        firing the job."""
        async def boom():
            raise RuntimeError("db is unreachable")
        monkeypatch.setattr(sched, "run_scan_watchdog_sweep", boom)

        loop = asyncio.new_event_loop()
        thread = threading.Thread(target=loop.run_forever, daemon=True)
        thread.start()
        sched._app_loop = loop
        try:
            sched._run_watchdog_job()  # must not raise
        finally:
            loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=2)
            loop.close()


# ── 5. Lifecycle — start/stop/status ─────────────────────────────────────────

class TestLifecycle:
    def test_start_scheduler_runs_and_configures_interval(self, monkeypatch):
        monkeypatch.setenv("SCAN_WATCHDOG_SWEEP_INTERVAL_MINUTES", "15")
        scheduler = sched.start_scheduler(asyncio.new_event_loop())
        try:
            assert scheduler.running is True
            job = scheduler.get_job(sched.JOB_ID)
            assert job is not None
            assert job.trigger.interval == timedelta(minutes=15)
        finally:
            sched.stop_scheduler()

    def test_start_is_idempotent(self, monkeypatch):
        monkeypatch.setenv("SCAN_WATCHDOG_SWEEP_INTERVAL_MINUTES", "30")
        s1 = sched.start_scheduler(asyncio.new_event_loop())
        s2 = sched.start_scheduler(asyncio.new_event_loop())
        assert s1 is s2
        sched.stop_scheduler()

    def test_stop_before_start_is_safe(self):
        sched.stop_scheduler()  # no-op, must not raise

    def test_get_status_reflects_running_state(self, monkeypatch):
        monkeypatch.setenv("SCAN_WATCHDOG_SWEEP_INTERVAL_MINUTES", "20")
        monkeypatch.setenv("SCAN_WATCHDOG_STALE_TIMEOUT_HOURS", "3")
        assert sched.get_status()["running"] is False

        sched.start_scheduler(asyncio.new_event_loop())
        status = sched.get_status()
        assert status["running"] is True
        assert status["interval_minutes"] == 20.0
        assert status["stale_timeout_hours"] == 3.0
        assert status["next_run_at"] is not None

        sched.stop_scheduler()
        assert sched.get_status()["running"] is False

    def test_get_status_reports_last_run_summary(self, db, monkeypatch):
        monkeypatch.setenv("SCAN_WATCHDOG_STALE_TIMEOUT_HOURS", "2")
        long_ago = datetime.utcnow() - timedelta(hours=5)

        async def seed():
            uid = await _seed_user(db)
            await _seed_scan(db, uid, "stale-running", status="running", started_at=long_ago)
        _run(seed())

        _run(sched.run_scan_watchdog_sweep())
        status = sched.get_status()
        assert status["last_run_at"] is not None
        assert status["last_run_summary"]["reaped"] == 1
