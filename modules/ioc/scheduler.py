"""
IOC OTX periodic sync — background scheduler.

Turns IOCEngine.sync_from_otx() into a periodic sweep that keeps the local
IOC store (web.models.Ioc) refreshed with the latest AlienVault OTX pulse
indicators, so GET /api/iocs/search and /api/iocs/scan/{id}/matches have
current threat-feed data to correlate scan findings against without a
manual POST /api/iocs/sync call.

Design notes — deliberately mirrors modules/darkweb/scheduler.py exactly,
not a fresh design, because that module's topology is what's actually
proven safe in this app's deployment (see its own docstring for the full
reasoning):
  - Uses APScheduler's BackgroundScheduler (its own thread, not the asyncio
    event loop). Each firing hands the coroutine off to the *app's* event
    loop via `asyncio.run_coroutine_threadsafe()` (captured in
    `start_scheduler()`) rather than `asyncio.run()`, because the shared
    asyncpg connection pool in web.database is a single process-wide
    engine — a pooled connection opened on one loop handed to a
    freshly-created loop raises "Future ... attached to a different loop"
    the moment it's awaited.
  - Render deploys this app with `--workers 2`, so two independent
    processes each start their own BackgroundScheduler on the same
    interval. Every firing first tries to acquire a DB-backed lock
    (SchedulerLock, the same job-agnostic table/model the dark web
    scheduler uses, just a different job_name) before touching OTX or the
    Ioc table; a process that loses the race just logs and returns. The
    lock has a staleness threshold so a worker that dies mid-sync can
    never wedge the job forever.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import or_, select, update

logger = logging.getLogger("ioc.scheduler")

JOB_ID = "ioc_otx_sync_periodic"
LOCK_NAME = "ioc_otx_sync"

# Identifies this process for lock bookkeeping/logging — unique per worker.
WORKER_ID = f"{os.getpid()}-{uuid.uuid4().hex[:8]}"

# How long a held lock is honored before being treated as abandoned (e.g.
# the holder crashed or was killed mid-sync by a redeploy). Independent of
# the sync interval itself — bounds worst-case staleness, not sync cadence.
_DEFAULT_LOCK_STALE_HOURS = 2.0

_scheduler: BackgroundScheduler | None = None
_app_loop: asyncio.AbstractEventLoop | None = None
_last_run_at: datetime | None = None
_last_run_summary: dict | None = None


def get_sync_interval_hours() -> float:
    """IOC_OTX_SYNC_INTERVAL_HOURS env var, default 6h — shorter than the
    dark web scheduler's 24h default since OTX pulses churn faster than
    breach/leak sources. Falls back to the default on missing/invalid
    values rather than failing startup."""
    raw = os.environ.get("IOC_OTX_SYNC_INTERVAL_HOURS", "6")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        logger.warning("invalid IOC_OTX_SYNC_INTERVAL_HOURS=%r, using default 6h", raw)
        return 6.0
    return value if value > 0 else 6.0


def get_sync_limit() -> int:
    """IOC_OTX_SYNC_LIMIT env var, default 100 — how many OTX indicators to
    pull per sweep (passed straight to IOCEngine.sync_from_otx)."""
    raw = os.environ.get("IOC_OTX_SYNC_LIMIT", "100")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return 100
    return value if value > 0 else 100


def _get_lock_stale_hours() -> float:
    raw = os.environ.get("IOC_OTX_SYNC_LOCK_STALE_HOURS", str(_DEFAULT_LOCK_STALE_HOURS))
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return _DEFAULT_LOCK_STALE_HOURS
    return value if value > 0 else _DEFAULT_LOCK_STALE_HOURS


# ── DB lock ──────────────────────────────────────────────────────────────
# Identical logic to modules/darkweb/scheduler.py's _acquire_lock/_release_lock
# — kept as its own copy (not a shared helper) so each scheduler module stays
# independently readable/testable, same as the two modules today.

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


# ── Sync ─────────────────────────────────────────────────────────────────

async def run_scheduled_sync() -> dict:
    """
    One full periodic sync: acquire the DB lock, run IOCEngine.sync_from_otx()
    against a fresh session/repository, then release the lock.

    Returns a summary dict (also stored for the status endpoint). Never
    raises — sync_from_otx() already swallows its own fetch failures, and
    any other error here is logged and returned as a summary rather than
    propagated, so it can't kill the scheduler thread.
    """
    global _last_run_at, _last_run_summary

    from web import database as _db

    stale_after = timedelta(hours=_get_lock_stale_hours())

    async with _db.SessionLocal() as db:
        acquired = await _acquire_lock(db, LOCK_NAME, WORKER_ID, stale_after)

    if not acquired:
        logger.info("ioc scheduler: lock held by another worker, skipping this run")
        return {"skipped": True, "reason": "lock_held"}

    summary = {"fetched": 0, "stored": 0, "skipped": 0}
    try:
        from modules.ioc.ioc_engine import IOCEngine, IOCRepository

        async with _db.SessionLocal() as db:
            engine = IOCEngine(repository=IOCRepository(db))
            summary = await engine.sync_from_otx(limit=get_sync_limit())
            await db.commit()

        logger.info("ioc scheduler: sync complete — %s", summary)
    except Exception:
        logger.exception("ioc scheduler: sync failed")
        summary = {"fetched": 0, "stored": 0, "skipped": 0, "error": "sync_failed"}
    finally:
        async with _db.SessionLocal() as db:
            await _release_lock(db, LOCK_NAME, WORKER_ID)

    _last_run_at = datetime.utcnow()
    _last_run_summary = summary
    return summary


def _run_sync_job() -> None:
    """Sync entrypoint APScheduler calls on its own thread.

    Submits the coroutine to the app's event loop (`_app_loop`, captured by
    `start_scheduler()`) instead of `asyncio.run()` — see the module
    docstring for why mixing loops there raises "attached to a different
    loop". `.result()` blocks this scheduler thread only; it doesn't block
    the app loop, which keeps serving requests concurrently while the
    coroutine runs on it.
    """
    try:
        future = asyncio.run_coroutine_threadsafe(run_scheduled_sync(), _app_loop)
        future.result()
    except Exception:
        logger.exception("ioc scheduler: sync crashed")


# ── Lifecycle ────────────────────────────────────────────────────────────

def start_scheduler(loop: asyncio.AbstractEventLoop | None = None) -> BackgroundScheduler:
    """Start the periodic OTX sync. Safe to call more than once — a second
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

    interval_hours = get_sync_interval_hours()
    _scheduler = BackgroundScheduler(timezone="UTC")
    _scheduler.add_job(
        _run_sync_job,
        trigger=IntervalTrigger(hours=interval_hours),
        id=JOB_ID,
        next_run_time=datetime.utcnow() + timedelta(seconds=90),
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
        replace_existing=True,
    )
    _scheduler.start()
    logger.info(
        "ioc scheduler started — interval=%.2fh worker_id=%s first_run_in=90s",
        interval_hours, WORKER_ID,
    )
    return _scheduler


def stop_scheduler() -> None:
    """Stop the scheduler cleanly. Safe to call even if never started."""
    global _scheduler, _app_loop
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        logger.info("ioc scheduler stopped worker_id=%s", WORKER_ID)
    _scheduler = None
    _app_loop = None


def get_status() -> dict:
    """Snapshot for GET /api/iocs/scheduler/status."""
    running = _scheduler is not None and _scheduler.running
    next_run_at = None
    if running:
        job = _scheduler.get_job(JOB_ID)
        if job is not None and job.next_run_time is not None:
            next_run_at = job.next_run_time.isoformat()

    return {
        "running": running,
        "interval_hours": get_sync_interval_hours(),
        "worker_id": WORKER_ID,
        "last_run_at": _last_run_at.isoformat() if _last_run_at else None,
        "last_run_summary": _last_run_summary,
        "next_run_at": next_run_at,
    }
