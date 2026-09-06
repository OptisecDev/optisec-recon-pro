"""
Scan Watchdog — periodic sweep for orphaned scans

A `Scan` row's `status` only ever transitions to "done"/"failed" from inside
`_run_scan_task`'s own try/except (web/app.py). If the whole process is
killed mid-task (Render redeploy, OOM, crash) before that handler runs, the
row is left orphaned at "running" (or "pending", if the worker died before
even starting) forever — nothing else ever revisits it. This sweep finds
such rows and marks them "failed" automatically.

Design notes (mirrors modules/darkweb/scheduler.py and modules/ioc/scheduler.py):
  - Uses APScheduler's BackgroundScheduler (its own thread, not the asyncio
    event loop) so sweep firing time is decoupled from how busy the app's
    event loop is. Each firing hands the coroutine off to the *app's* event
    loop via `asyncio.run_coroutine_threadsafe()` (captured in
    `start_scheduler()`) rather than `asyncio.run()`. `asyncio.run()` would
    spin up a brand new loop per firing, and since the shared asyncpg
    connection pool in web.database is a single process-wide engine, any
    pooled connection opened on one loop would get handed to the new loop
    and raise "Future ... attached to a different loop" the moment it's
    awaited. Running every firing on the same app loop that owns the pool
    avoids this entirely.
  - Render deploys this app with `--workers 2`, so two independent processes
    each start their own BackgroundScheduler on the same interval. To keep
    the sweep from running twice, every firing first tries to acquire a
    DB-backed lock (SchedulerLock, an atomic conditional UPDATE keyed on
    job_name) before touching any scans; a process that loses the race just
    logs and returns. The lock has a staleness threshold so a worker that
    dies mid-sweep can never wedge the job forever.
  - The staleness threshold for what counts as an orphaned scan
    (SCAN_WATCHDOG_STALE_TIMEOUT_HOURS, default 2h) is independent of the
    sweep's own cadence (SCAN_WATCHDOG_SWEEP_INTERVAL_MINUTES, default 30m)
    and of the lock's staleness threshold (SCAN_WATCHDOG_LOCK_STALE_HOURS,
    default 1h) — three separate knobs for three separate concerns.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import func, or_, select, update

logger = logging.getLogger("scan_watchdog.scheduler")

JOB_ID = "scan_watchdog_sweep"
LOCK_NAME = "scan_watchdog"

# Identifies this process for lock bookkeeping/logging — unique per worker.
WORKER_ID = f"{os.getpid()}-{uuid.uuid4().hex[:8]}"

# How long a held lock is honored before being treated as abandoned. Shorter
# than darkweb's default since this sweep's own cadence is 30m, not 24h — a
# lock held longer than 1h is clearly abandoned, not just a slow sweep.
_DEFAULT_LOCK_STALE_HOURS = 1.0

_scheduler: BackgroundScheduler | None = None
_app_loop: asyncio.AbstractEventLoop | None = None
_last_run_at: datetime | None = None
_last_run_summary: dict | None = None


def get_sweep_interval_minutes() -> float:
    """SCAN_WATCHDOG_SWEEP_INTERVAL_MINUTES env var, default 30m. Falls back
    to the default on missing/invalid values rather than failing startup."""
    raw = os.environ.get("SCAN_WATCHDOG_SWEEP_INTERVAL_MINUTES", "30")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        logger.warning("invalid SCAN_WATCHDOG_SWEEP_INTERVAL_MINUTES=%r, using default 30m", raw)
        return 30.0
    return value if value > 0 else 30.0


def get_stale_timeout_hours() -> float:
    """SCAN_WATCHDOG_STALE_TIMEOUT_HOURS env var, default 2h. A scan still
    "running"/"pending" past this age is considered orphaned."""
    raw = os.environ.get("SCAN_WATCHDOG_STALE_TIMEOUT_HOURS", "2")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        logger.warning("invalid SCAN_WATCHDOG_STALE_TIMEOUT_HOURS=%r, using default 2h", raw)
        return 2.0
    return value if value > 0 else 2.0


def _get_lock_stale_hours() -> float:
    raw = os.environ.get("SCAN_WATCHDOG_LOCK_STALE_HOURS", str(_DEFAULT_LOCK_STALE_HOURS))
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

async def run_scan_watchdog_sweep() -> dict:
    """
    One full periodic sweep: acquire the DB lock, mark every scan still
    "running" or "pending" past the staleness threshold as "failed", then
    release the lock.

    Returns a summary dict (also stored for the status endpoint). Never
    raises — failures are logged, not propagated, so a lost DB connection
    can't kill the scheduler thread.
    """
    global _last_run_at, _last_run_summary

    from web import database as _db
    from web.models import Scan

    stale_after = timedelta(hours=_get_lock_stale_hours())

    async with _db.SessionLocal() as db:
        acquired = await _acquire_lock(db, LOCK_NAME, WORKER_ID, stale_after)

    if not acquired:
        logger.info("scan watchdog: lock held by another worker, skipping this run")
        return {"skipped": True, "reason": "lock_held"}

    summary = {"reaped": 0, "reaped_scan_ids": []}
    try:
        stale_timeout_hours = get_stale_timeout_hours()
        stale_before = datetime.utcnow() - timedelta(hours=stale_timeout_hours)
        reaped_ids: list[str] = []

        async with _db.SessionLocal() as db:
            for prev_status in ("running", "pending"):
                error_message = (
                    "Scan marked as failed by the automated watchdog: the "
                    "underlying process (nmap subprocess / parent worker) "
                    f"appears to have terminated or hung without reporting "
                    f"completion. Orphaned in '{prev_status}' state for over "
                    f"{stale_timeout_hours}h with no activity. Not a "
                    "scan-logic failure."
                )
                result = await db.execute(
                    update(Scan)
                    .where(Scan.status == prev_status)
                    .where(func.coalesce(Scan.started_at, Scan.created_at) < stale_before)
                    .values(status="failed", error=error_message, completed_at=datetime.utcnow())
                    .returning(Scan.id)
                )
                reaped_ids.extend(row[0] for row in result.fetchall())
            await db.commit()

        summary["reaped"] = len(reaped_ids)
        summary["reaped_scan_ids"] = reaped_ids[:20]
        if reaped_ids:
            logger.warning("scan watchdog: reaped %d orphaned scan(s): %s", len(reaped_ids), reaped_ids)
        else:
            logger.info("scan watchdog: sweep complete — nothing to reap")
    except Exception:
        logger.exception("scan watchdog: sweep failed")
    finally:
        async with _db.SessionLocal() as db:
            await _release_lock(db, LOCK_NAME, WORKER_ID)

    _last_run_at = datetime.utcnow()
    _last_run_summary = summary
    return summary


def _run_watchdog_job() -> None:
    """Sync entrypoint APScheduler calls on its own thread.

    Submits the coroutine to the app's event loop (`_app_loop`, captured by
    `start_scheduler()`) instead of `asyncio.run()` — see the module
    docstring for why mixing loops raises "attached to a different loop".
    `.result()` blocks this scheduler thread only; it doesn't block the app
    loop, which keeps serving requests concurrently while the coroutine
    runs on it.
    """
    try:
        future = asyncio.run_coroutine_threadsafe(run_scan_watchdog_sweep(), _app_loop)
        future.result()
    except Exception:
        logger.exception("scan watchdog: sweep crashed")


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

    interval_minutes = get_sweep_interval_minutes()
    _scheduler = BackgroundScheduler(timezone="UTC")
    _scheduler.add_job(
        _run_watchdog_job,
        trigger=IntervalTrigger(minutes=interval_minutes),
        id=JOB_ID,
        next_run_time=datetime.utcnow() + timedelta(seconds=60),
        max_instances=1,
        coalesce=True,
        misfire_grace_time=1800,
        replace_existing=True,
    )
    _scheduler.start()
    logger.info(
        "scan watchdog started — interval=%.1fm stale_timeout=%.1fh worker_id=%s first_run_in=60s",
        interval_minutes, get_stale_timeout_hours(), WORKER_ID,
    )
    return _scheduler


def stop_scheduler() -> None:
    """Stop the scheduler cleanly. Safe to call even if never started."""
    global _scheduler, _app_loop
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        logger.info("scan watchdog stopped worker_id=%s", WORKER_ID)
    _scheduler = None
    _app_loop = None


def get_status() -> dict:
    """Snapshot for GET /api/admin/scan-watchdog/status."""
    running = _scheduler is not None and _scheduler.running
    next_run_at = None
    if running:
        job = _scheduler.get_job(JOB_ID)
        if job is not None and job.next_run_time is not None:
            next_run_at = job.next_run_time.isoformat()

    return {
        "running": running,
        "interval_minutes": get_sweep_interval_minutes(),
        "stale_timeout_hours": get_stale_timeout_hours(),
        "worker_id": WORKER_ID,
        "last_run_at": _last_run_at.isoformat() if _last_run_at else None,
        "last_run_summary": _last_run_summary,
        "next_run_at": next_run_at,
    }
