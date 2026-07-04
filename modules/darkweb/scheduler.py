"""
Dark Web Monitoring — periodic scan scheduler

Turns the manual POST /api/darkweb/monitor/{id}/check endpoint into a
background sweep that periodically re-checks every active DarkWebMonitor
target, persisting new leak events as DarkWebAlert rows exactly like a
manual check does (via web.routers.darkweb_monitor.run_check_and_persist).

Design notes:
  - Uses APScheduler's BackgroundScheduler (its own thread, not the asyncio
    event loop) so scan firing time is decoupled from how busy the app's
    event loop is. Each firing hands the coroutine off to the *app's*
    event loop via `asyncio.run_coroutine_threadsafe()` (captured in
    `start_scheduler()`) rather than `asyncio.run()`. `asyncio.run()` would
    spin up a brand new loop per firing, and since the shared asyncpg
    connection pool in web.database is a single process-wide engine, any
    pooled connection opened on one loop (e.g. the app's main loop during
    startup, or a previous firing's now-closed loop) would get handed to
    the new loop and raise "Future ... attached to a different loop" the
    moment it's awaited. Running every firing on the same app loop that
    owns the pool avoids this entirely.
  - Render deploys this app with `--workers 2` (see README's Deploy to
    Render section), so two independent processes each start their own
    BackgroundScheduler on the same interval. To keep the sweep from
    running twice, every firing first tries to acquire a DB-backed lock
    (SchedulerLock, an atomic conditional UPDATE keyed on job_name) before
    touching any targets; a process that loses the race just logs and
    returns. The lock has a staleness threshold so a worker that dies
    mid-sweep (e.g. a Render redeploy killing the old instance) can never
    wedge the job forever — the next firing simply reclaims it.
  - A monitor is only actually re-checked once its `last_checked_at` is
    older than the configured interval, computed in SQL. This makes
    restarts/redeploys cheap: the sweep fires ~60s after every startup,
    but on a fresh deploy most targets were already checked recently and
    the SQL WHERE clause skips them — so redeploying does not spam the
    upstream breach APIs.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select, or_, update

logger = logging.getLogger("darkweb.scheduler")

JOB_ID = "darkweb_periodic_scan"
LOCK_NAME = "darkweb_scan"

# Identifies this process for lock bookkeeping/logging — unique per worker.
WORKER_ID = f"{os.getpid()}-{uuid.uuid4().hex[:8]}"

# How long a held lock is honored before being treated as abandoned (e.g.
# the holder crashed or was killed mid-sweep by a redeploy). Independent of
# the scan interval itself — bounds worst-case staleness, not scan cadence.
_DEFAULT_LOCK_STALE_HOURS = 2.0

_scheduler: BackgroundScheduler | None = None
_app_loop: asyncio.AbstractEventLoop | None = None
_last_run_at: datetime | None = None
_last_run_summary: dict | None = None


def get_scan_interval_hours() -> float:
    """DARKWEB_SCAN_INTERVAL_HOURS env var, default 24h. Falls back to the
    default on missing/invalid values rather than failing startup."""
    raw = os.environ.get("DARKWEB_SCAN_INTERVAL_HOURS", "24")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        logger.warning("invalid DARKWEB_SCAN_INTERVAL_HOURS=%r, using default 24h", raw)
        return 24.0
    return value if value > 0 else 24.0


def _get_lock_stale_hours() -> float:
    raw = os.environ.get("DARKWEB_SCAN_LOCK_STALE_HOURS", str(_DEFAULT_LOCK_STALE_HOURS))
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return _DEFAULT_LOCK_STALE_HOURS
    return value if value > 0 else _DEFAULT_LOCK_STALE_HOURS


# ── DB lock ──────────────────────────────────────────────────────────────

async def _acquire_lock(db, job_name: str, worker_id: str, stale_after: timedelta) -> bool:
    """Atomically claim `job_name` for `worker_id` if it's unlocked or its
    lock is stale. Returns True iff this call won the lock."""
    from web.models import SchedulerLock

    row = (await db.execute(select(SchedulerLock).where(SchedulerLock.job_name == job_name))).scalar_one_or_none()
    if row is None:
        db.add(SchedulerLock(job_name=job_name, locked_at=None, locked_by=None))
        await db.commit()

    now = datetime.utcnow()
    stale_before = now - stale_after
    result = await db.execute(
        update(SchedulerLock)
        .where(SchedulerLock.job_name == job_name)
        .where(or_(SchedulerLock.locked_at.is_(None), SchedulerLock.locked_at < stale_before))
        .values(locked_at=now, locked_by=worker_id)
    )
    await db.commit()
    return result.rowcount == 1


async def _release_lock(db, job_name: str, worker_id: str) -> None:
    """Release the lock only if still held by `worker_id` — a stale lock
    that's since been reclaimed by another worker must not be cleared out
    from under it."""
    from web.models import SchedulerLock

    await db.execute(
        update(SchedulerLock)
        .where(SchedulerLock.job_name == job_name, SchedulerLock.locked_by == worker_id)
        .values(locked_at=None, locked_by=None)
    )
    await db.commit()


# ── Sweep ────────────────────────────────────────────────────────────────

async def run_scheduled_scan() -> dict:
    """
    One full periodic sweep: acquire the DB lock, find every active
    DarkWebMonitor not checked within the configured interval, check each
    one and persist new alerts, then release the lock.

    Returns a summary dict (also stored for the status endpoint). Never
    raises — failures are logged and counted, not propagated, so one bad
    target or a lost DB connection can't kill the scheduler thread.
    """
    global _last_run_at, _last_run_summary

    from web import database as _db
    from web.models import DarkWebMonitor

    stale_after = timedelta(hours=_get_lock_stale_hours())

    async with _db.SessionLocal() as db:
        acquired = await _acquire_lock(db, LOCK_NAME, WORKER_ID, stale_after)

    if not acquired:
        logger.info("darkweb scheduler: lock held by another worker, skipping this run")
        return {"skipped": True, "reason": "lock_held"}

    summary = {"checked": 0, "skipped": 0, "failed": 0, "new_alerts": 0}
    try:
        interval_hours = get_scan_interval_hours()
        threshold = datetime.utcnow() - timedelta(hours=interval_hours)

        async with _db.SessionLocal() as db:
            due_ids = (await db.execute(
                select(DarkWebMonitor.id)
                .where(DarkWebMonitor.is_active == True)  # noqa: E712
                .where(or_(DarkWebMonitor.last_checked_at.is_(None), DarkWebMonitor.last_checked_at < threshold))
            )).scalars().all()

            total_active = (await db.execute(
                select(DarkWebMonitor.id).where(DarkWebMonitor.is_active == True)  # noqa: E712
            )).scalars().all()
        summary["skipped"] = len(total_active) - len(due_ids)

        from web.routers.darkweb_monitor import run_check_and_persist

        for monitor_id in due_ids:
            try:
                async with _db.SessionLocal() as db:
                    monitor = await db.get(DarkWebMonitor, monitor_id)
                    if not monitor or not monitor.is_active:
                        continue
                    new_alerts, _result = await run_check_and_persist(monitor, db)
                summary["checked"] += 1
                summary["new_alerts"] += len(new_alerts)
                logger.info(
                    "darkweb scheduler: checked target=%r new_alerts=%d",
                    monitor.target, len(new_alerts),
                )
            except Exception:
                summary["failed"] += 1
                logger.exception("darkweb scheduler: check failed for monitor_id=%s", monitor_id)

        logger.info("darkweb scheduler: sweep complete — %s", summary)
    finally:
        async with _db.SessionLocal() as db:
            await _release_lock(db, LOCK_NAME, WORKER_ID)

    _last_run_at = datetime.utcnow()
    _last_run_summary = summary
    return summary


def _run_scan_job() -> None:
    """Sync entrypoint APScheduler calls on its own thread.

    Submits the coroutine to the app's event loop (`_app_loop`, captured by
    `start_scheduler()`) instead of `asyncio.run()`, so every DB call in
    `run_scheduled_scan()` runs on the same loop that owns the shared
    asyncpg connection pool — see the module docstring for why mixing
    loops there raises "attached to a different loop". `.result()` blocks
    this scheduler thread only; it doesn't block the app loop, which keeps
    serving requests concurrently while the coroutine runs on it.
    """
    try:
        future = asyncio.run_coroutine_threadsafe(run_scheduled_scan(), _app_loop)
        future.result()
    except Exception:
        logger.exception("darkweb scheduler: sweep crashed")


# ── Lifecycle ────────────────────────────────────────────────────────────

def start_scheduler(loop: asyncio.AbstractEventLoop | None = None) -> BackgroundScheduler:
    """Start the periodic sweep. Safe to call more than once — a second
    call is a no-op while the scheduler is already running.

    `loop` must be the event loop that owns the app's shared DB engine
    (web.database.engine) — every firing runs on it via
    run_coroutine_threadsafe. Defaults to the currently running loop, which
    is correct when called from within FastAPI's `startup` event handler.
    """
    global _scheduler, _app_loop
    if _scheduler is not None and _scheduler.running:
        return _scheduler

    _app_loop = loop if loop is not None else asyncio.get_running_loop()

    interval_hours = get_scan_interval_hours()
    _scheduler = BackgroundScheduler(timezone="UTC")
    _scheduler.add_job(
        _run_scan_job,
        trigger=IntervalTrigger(hours=interval_hours),
        id=JOB_ID,
        next_run_time=datetime.utcnow() + timedelta(seconds=60),
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
        replace_existing=True,
    )
    _scheduler.start()
    logger.info(
        "darkweb scheduler started — interval=%.2fh worker_id=%s first_run_in=60s",
        interval_hours, WORKER_ID,
    )
    return _scheduler


def stop_scheduler() -> None:
    """Stop the scheduler cleanly. Safe to call even if never started."""
    global _scheduler, _app_loop
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        logger.info("darkweb scheduler stopped worker_id=%s", WORKER_ID)
    _scheduler = None
    _app_loop = None


def get_status() -> dict:
    """Snapshot for GET /api/darkweb/scheduler/status."""
    running = _scheduler is not None and _scheduler.running
    next_run_at = None
    if running:
        job = _scheduler.get_job(JOB_ID)
        if job is not None and job.next_run_time is not None:
            next_run_at = job.next_run_time.isoformat()

    return {
        "running": running,
        "interval_hours": get_scan_interval_hours(),
        "worker_id": WORKER_ID,
        "last_run_at": _last_run_at.isoformat() if _last_run_at else None,
        "last_run_summary": _last_run_summary,
        "next_run_at": next_run_at,
    }
