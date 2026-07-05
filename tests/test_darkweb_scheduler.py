"""
Tests for the Dark Web Monitoring periodic scheduler
(modules/darkweb/scheduler.py).

Mirrors tests/test_darkweb_monitor.py's conventions: plain pytest, async
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
from web.models import User, DarkWebMonitor, DarkWebAlert, SchedulerLock
import modules.darkweb.scheduler as sched


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


async def _seed_monitor(session_factory, user_id: int, target: str,
                         last_checked_at=None, is_active: bool = True) -> int:
    async with session_factory() as db_:
        m = DarkWebMonitor(user_id=user_id, target=target, target_type="domain",
                            label=target, is_active=is_active, last_checked_at=last_checked_at)
        db_.add(m)
        await db_.commit()
        await db_.refresh(m)
        return m.id


def _patch_check(monkeypatch, calls: list):
    """Stub out the real scan+diff+persist call so no network I/O happens
    and we can assert exactly which targets the sweep decided to check."""
    async def fake_check(monitor, db_):
        calls.append(monitor.target)
        return [], {"events": [], "exposure": {}}
    monkeypatch.setattr("web.routers.darkweb_monitor.run_check_and_persist", fake_check)


# ── 1. Interval configuration (mocked "timing") ──────────────────────────────

class TestIntervalConfig:
    def test_default_is_24_hours(self, monkeypatch):
        monkeypatch.delenv("DARKWEB_SCAN_INTERVAL_HOURS", raising=False)
        assert sched.get_scan_interval_hours() == 24.0

    def test_reads_custom_env_value(self, monkeypatch):
        monkeypatch.setenv("DARKWEB_SCAN_INTERVAL_HOURS", "6")
        assert sched.get_scan_interval_hours() == 6.0

    def test_invalid_value_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("DARKWEB_SCAN_INTERVAL_HOURS", "not-a-number")
        assert sched.get_scan_interval_hours() == 24.0

    def test_non_positive_value_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("DARKWEB_SCAN_INTERVAL_HOURS", "0")
        assert sched.get_scan_interval_hours() == 24.0
        monkeypatch.setenv("DARKWEB_SCAN_INTERVAL_HOURS", "-5")
        assert sched.get_scan_interval_hours() == 24.0


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


# ── 3. run_scheduled_scan — which targets get checked ────────────────────────

class TestRunScheduledScan:
    def test_checks_only_due_targets(self, db, monkeypatch):
        monkeypatch.setenv("DARKWEB_SCAN_INTERVAL_HOURS", "24")

        async def seed():
            uid = await _seed_user(db)
            await _seed_monitor(db, uid, "never-checked.com", last_checked_at=None)
            await _seed_monitor(db, uid, "checked-recently.com", last_checked_at=datetime.utcnow())
            await _seed_monitor(db, uid, "checked-long-ago.com",
                                last_checked_at=datetime.utcnow() - timedelta(hours=48))
        _run(seed())

        calls = []
        _patch_check(monkeypatch, calls)

        summary = _run(sched.run_scheduled_scan())
        assert sorted(calls) == ["checked-long-ago.com", "never-checked.com"]
        assert summary["checked"] == 2
        assert summary["skipped"] == 1
        assert summary["failed"] == 0

    def test_inactive_monitors_are_never_checked(self, db, monkeypatch):
        async def seed():
            uid = await _seed_user(db)
            await _seed_monitor(db, uid, "disabled.com", last_checked_at=None, is_active=False)
        _run(seed())

        calls = []
        _patch_check(monkeypatch, calls)

        summary = _run(sched.run_scheduled_scan())
        assert calls == []
        assert summary["checked"] == 0
        assert summary["skipped"] == 0

    def test_one_failing_target_does_not_abort_the_sweep(self, db, monkeypatch):
        async def seed():
            uid = await _seed_user(db)
            await _seed_monitor(db, uid, "boom.com", last_checked_at=None)
            await _seed_monitor(db, uid, "fine.com", last_checked_at=None)
        _run(seed())

        calls = []

        async def flaky_check(monitor, db_):
            if monitor.target == "boom.com":
                raise RuntimeError("upstream API exploded")
            calls.append(monitor.target)
            return [], {"events": [], "exposure": {}}
        monkeypatch.setattr("web.routers.darkweb_monitor.run_check_and_persist", flaky_check)

        summary = _run(sched.run_scheduled_scan())
        assert calls == ["fine.com"]
        assert summary["checked"] == 1
        assert summary["failed"] == 1

    def test_lock_prevents_duplicate_sweep(self, db, monkeypatch):
        """Simulates a second worker/instance firing the same job while the
        first already holds the lock — it must skip entirely, calling the
        scan for nobody."""
        async def seed():
            uid = await _seed_user(db)
            await _seed_monitor(db, uid, "due.com", last_checked_at=None)
            async with db() as db_:
                db_.add(SchedulerLock(job_name=sched.LOCK_NAME, locked_at=datetime.utcnow(),
                                       locked_by="other-worker-already-running"))
                await db_.commit()
        _run(seed())

        calls = []
        _patch_check(monkeypatch, calls)

        summary = _run(sched.run_scheduled_scan())
        assert calls == []
        assert summary == {"skipped": True, "reason": "lock_held"}

    def test_lock_is_released_after_the_sweep_so_the_next_run_can_proceed(self, db, monkeypatch):
        async def seed():
            uid = await _seed_user(db)
            await _seed_monitor(db, uid, "due.com", last_checked_at=None)
        _run(seed())

        calls = []
        _patch_check(monkeypatch, calls)

        _run(sched.run_scheduled_scan())
        assert calls == ["due.com"]

        async def lock_row():
            async with db() as db_:
                return (await db_.execute(
                    select(SchedulerLock).where(SchedulerLock.job_name == sched.LOCK_NAME)
                )).scalar_one()
        row = _run(lock_row())
        assert row.locked_at is None
        assert row.locked_by is None

    def test_lock_is_released_even_if_a_target_check_raises(self, db, monkeypatch):
        async def seed():
            uid = await _seed_user(db)
            await _seed_monitor(db, uid, "boom.com", last_checked_at=None)
        _run(seed())

        async def always_fails(monitor, db_):
            raise RuntimeError("upstream API exploded")
        monkeypatch.setattr("web.routers.darkweb_monitor.run_check_and_persist", always_fails)

        _run(sched.run_scheduled_scan())

        async def lock_row():
            async with db() as db_:
                return (await db_.execute(
                    select(SchedulerLock).where(SchedulerLock.job_name == sched.LOCK_NAME)
                )).scalar_one()
        row = _run(lock_row())
        assert row.locked_at is None

    def test_end_to_end_persists_new_alert_via_real_check_and_persist(self, db, monkeypatch):
        """Exercises the real web.routers.darkweb_monitor.run_check_and_persist
        (not stubbed) so the scheduler's DB writes are verified, not just
        that it decided to call something."""
        async def fake_run_monitor_check(target, target_type=None, include_pastes=True, include_github=True):
            return {
                "target": target, "target_type": target_type or "domain",
                "events": [{"fingerprint": "fp1", "source": "breach", "severity": "critical",
                            "title": "Test Breach", "detail": {}}],
                "exposure": {"score": 10, "exposure_level": "Exposed"},
                "leakcheck": {"found": False},
                "checked_at": datetime.utcnow().isoformat(),
            }
        monkeypatch.setattr("modules.darkweb.monitor.run_monitor_check", fake_run_monitor_check)

        async def seed():
            uid = await _seed_user(db)
            return await _seed_monitor(db, uid, "due.com", last_checked_at=None)
        monitor_id = _run(seed())

        summary = _run(sched.run_scheduled_scan())
        assert summary["checked"] == 1
        assert summary["new_alerts"] == 1

        async def stored_alerts():
            async with db() as db_:
                return (await db_.execute(
                    select(DarkWebAlert).where(DarkWebAlert.monitor_id == monitor_id)
                )).scalars().all()
        alerts = _run(stored_alerts())
        assert len(alerts) == 1
        assert alerts[0].fingerprint == "fp1"
        assert alerts[0].severity == "critical"

        async def checked_monitor():
            async with db() as db_:
                return await db_.get(DarkWebMonitor, monitor_id)
        monitor = _run(checked_monitor())
        assert monitor.last_checked_at is not None

    def test_second_run_does_not_re_alert_on_the_same_leak(self, db, monkeypatch):
        """A leak already stored from a previous sweep must not be
        re-persisted as a new alert on the next sweep."""
        async def fake_run_monitor_check(target, target_type=None, include_pastes=True, include_github=True):
            return {
                "target": target, "target_type": target_type or "domain",
                "events": [{"fingerprint": "fp1", "source": "breach", "severity": "critical",
                            "title": "Test Breach", "detail": {}}],
                "exposure": {}, "leakcheck": {"found": False}, "checked_at": datetime.utcnow().isoformat(),
            }
        monkeypatch.setattr("modules.darkweb.monitor.run_monitor_check", fake_run_monitor_check)

        async def seed():
            uid = await _seed_user(db)
            return await _seed_monitor(db, uid, "due.com", last_checked_at=None)
        monitor_id = _run(seed())

        first = _run(sched.run_scheduled_scan())
        assert first["new_alerts"] == 1

        async def make_due_again():
            async with db() as db_:
                m = await db_.get(DarkWebMonitor, monitor_id)
                m.last_checked_at = datetime.utcnow() - timedelta(hours=48)
                await db_.commit()
        _run(make_due_again())

        second = _run(sched.run_scheduled_scan())
        assert second["checked"] == 1
        assert second["new_alerts"] == 0

        async def stored_alerts():
            async with db() as db_:
                return (await db_.execute(
                    select(DarkWebAlert).where(DarkWebAlert.monitor_id == monitor_id)
                )).scalars().all()
        assert len(_run(stored_alerts())) == 1


# ── 4. _run_scan_job — the sync APScheduler entrypoint never raises ─────────

class TestRunScanJob:
    def test_never_raises_even_if_the_sweep_crashes(self, monkeypatch):
        """_run_scan_job submits to sched._app_loop via run_coroutine_threadsafe
        (see modules/darkweb/scheduler.py's module docstring for why: reusing
        asyncio.run()'s brand-new loop per firing corrupts the shared asyncpg
        pool). Mirror that topology here — a loop running on its own thread,
        stands in for the app's event loop, while this test thread plays the
        part of APScheduler's own thread firing the job."""
        async def boom():
            raise RuntimeError("db is unreachable")
        monkeypatch.setattr(sched, "run_scheduled_scan", boom)

        loop = asyncio.new_event_loop()
        thread = threading.Thread(target=loop.run_forever, daemon=True)
        thread.start()
        sched._app_loop = loop
        try:
            sched._run_scan_job()  # must not raise
        finally:
            loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=2)
            loop.close()


# ── 5. Lifecycle — start/stop/status ─────────────────────────────────────────

class TestLifecycle:
    def test_start_scheduler_runs_and_configures_interval(self, monkeypatch):
        monkeypatch.setenv("DARKWEB_SCAN_INTERVAL_HOURS", "3")
        scheduler = sched.start_scheduler(asyncio.new_event_loop())
        try:
            assert scheduler.running is True
            job = scheduler.get_job(sched.JOB_ID)
            assert job is not None
            assert job.trigger.interval == timedelta(hours=3)
        finally:
            sched.stop_scheduler()

    def test_start_is_idempotent(self, monkeypatch):
        monkeypatch.setenv("DARKWEB_SCAN_INTERVAL_HOURS", "24")
        s1 = sched.start_scheduler(asyncio.new_event_loop())
        s2 = sched.start_scheduler(asyncio.new_event_loop())
        assert s1 is s2
        sched.stop_scheduler()

    def test_stop_before_start_is_safe(self):
        sched.stop_scheduler()  # no-op, must not raise

    def test_get_status_reflects_running_state(self, monkeypatch):
        monkeypatch.setenv("DARKWEB_SCAN_INTERVAL_HOURS", "12")
        assert sched.get_status()["running"] is False

        sched.start_scheduler(asyncio.new_event_loop())
        status = sched.get_status()
        assert status["running"] is True
        assert status["interval_hours"] == 12.0
        assert status["next_run_at"] is not None

        sched.stop_scheduler()
        assert sched.get_status()["running"] is False

    def test_get_status_reports_last_run_summary(self, db, monkeypatch):
        async def seed():
            uid = await _seed_user(db)
            await _seed_monitor(db, uid, "due.com", last_checked_at=None)
        _run(seed())
        _patch_check(monkeypatch, [])

        _run(sched.run_scheduled_scan())
        status = sched.get_status()
        assert status["last_run_at"] is not None
        assert status["last_run_summary"]["checked"] == 1
