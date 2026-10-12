"""
Dark Web Monitoring router — persistent watchlist + new-leak alerting.

Layered on top of /api/osint/darkweb-scan's one-shot
gather_darkweb_intelligence(): a user adds a domain/email to a watchlist
(DarkWebMonitor), and each check run (POST .../check) diffs the freshly
gathered leak events against what's already stored (DarkWebAlert,
deduped by fingerprint) so only genuinely new leaks are persisted and
surfaced as alerts, each with a discovery timestamp.
"""

import logging
import os
from datetime import datetime

from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import select, case, func, update, delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import get_db
from web.models import User, DarkWebMonitor, DarkWebAlert
from web.auth import get_current_user
from web.license import require_feature_or_402
from web.rate_limit import rate_limiter

logger = logging.getLogger("darkweb.monitor.router")
router = APIRouter(prefix="/api/darkweb", tags=["darkweb-monitor"])

# run_check_and_persist() -> run_monitor_check() calls the exact same
# gather_darkweb_intelligence() as POST /api/osint/darkweb-scan (already
# rate-limited, see web/routers/osint.py's _darkweb_scan_limiter) plus
# LeakCheck -- multiple shared, instance-wide-keyed external APIs. Without
# its own limit, this endpoint was a second, unprotected path to the same
# calls, bypassing that earlier fix entirely.
_check_monitor_limiter = rate_limiter(
    "darkweb_monitor_check", lambda: int(os.environ.get("RATE_LIMIT_DARKWEB_MONITOR_CHECK", "10")), 60,
)


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _iso_utc(dt: datetime | None) -> str | None:
    """Timestamps are stored as naive UTC; without the trailing Z the browser
    would parse them as local time and show the wrong "last checked"."""
    return dt.isoformat() + "Z" if dt else None


def _monitor_to_dict(m: DarkWebMonitor) -> dict:
    return {
        "id": m.id, "target": m.target, "target_type": m.target_type,
        "label": m.label, "is_active": m.is_active,
        "created_at": _iso_utc(m.created_at),
        "last_checked_at": _iso_utc(m.last_checked_at),
        "validation_status": m.validation_status or "valid",
        "validation_error": m.validation_error,
        "last_check_error": m.last_check_error,
    }


def _alert_details(a: DarkWebAlert) -> dict:
    """Whitelisted, masked detail for the browser. Masking happens here (and
    already at write time) — raw matched values and any legacy un-sanitized
    `detail` keys never reach the client."""
    from modules.darkweb.targets import mask_value
    d = a.detail if isinstance(a.detail, dict) else {}
    matched_field = a.matched_field or d.get("matched_field")
    masked = d.get("matched_value_masked")
    return {
        "matched_field": matched_field,
        "matched_value_masked": mask_value(masked, matched_field) if masked else None,
        "source_name": d.get("source_name") or a.source,
        "provider": d.get("provider") or a.source,
        "leak_date": a.leak_date or d.get("leak_date"),
        "leaked_fields": list(a.leaked_fields or d.get("leaked_fields") or []),
        "reference_url": d.get("reference_url"),
    }


def _alert_to_dict(a: DarkWebAlert, target: str | None = None) -> dict:
    from modules.darkweb.monitor import SOURCE_LABELS_AR, SEVERITY_LABELS_AR
    return {
        "id": a.id, "monitor_id": a.monitor_id, "target": target,
        "source": a.source, "source_ar": SOURCE_LABELS_AR.get(a.source, a.source),
        "severity": a.severity, "severity_ar": SEVERITY_LABELS_AR.get(a.severity, a.severity),
        "title": a.title,
        "details": _alert_details(a),
        "discovered_at": _iso_utc(a.discovered_at),
        "acknowledged": a.acknowledged,
    }


def _bilingual_error(status: int, en: str, ar: str, **extra) -> JSONResponse:
    return JSONResponse(status_code=status, content={"detail": f"{ar} — {en}", "message_en": en,
                                                     "message_ar": ar, **extra})


async def _get_owned_monitor(monitor_id: int, user: User, db: AsyncSession) -> DarkWebMonitor:
    monitor = (await db.execute(
        select(DarkWebMonitor).where(DarkWebMonitor.id == monitor_id, DarkWebMonitor.user_id == user.id)
    )).scalar_one_or_none()
    if not monitor:
        raise HTTPException(404, "monitor not found")
    return monitor


class InvalidMonitorTarget(Exception):
    """Raised when a check is attempted on a monitor flagged invalid."""


async def mark_monitor_invalid(monitor: DarkWebMonitor, error: str, db: AsyncSession) -> int:
    """Flag `monitor` invalid and hide every alert it produced (cascade-hide —
    they came from a query against a malformed target). Returns the number of
    alerts hidden. Caller commits."""
    monitor.validation_status = "invalid"
    monitor.validation_error = error[:500]
    res = await db.execute(
        update(DarkWebAlert).where(DarkWebAlert.monitor_id == monitor.id, DarkWebAlert.hidden.is_(False))
        .values(hidden=True)
    )
    return res.rowcount or 0


def _visible_alerts_query(user_id: int):
    return (
        select(DarkWebAlert, DarkWebMonitor)
        .join(DarkWebMonitor, DarkWebAlert.monitor_id == DarkWebMonitor.id)
        .where(DarkWebMonitor.user_id == user_id)
        .where(DarkWebAlert.hidden.is_(False))
        .where(DarkWebMonitor.validation_status == "valid")
    )


_SEVERITY_RANK = case(
    {"critical": 0, "high": 1, "medium": 2, "low": 3}, value=DarkWebAlert.severity, else_=4,
)


async def visible_alerts_with_summary(user_id: int, db: AsyncSession, limit: int = 100,
                                      severity: str | None = None) -> dict:
    """Visible alerts across the user's valid monitors, most severe first
    (then newest), plus a per-severity count over *all* visible alerts.
    Shared by the /darkweb page render and GET /monitor/alerts/recent."""
    q = _visible_alerts_query(user_id)
    if severity:
        q = q.where(DarkWebAlert.severity == severity)
    rows = (await db.execute(
        q.order_by(_SEVERITY_RANK, DarkWebAlert.discovered_at.desc()).limit(limit)
    )).all()

    count_rows = (await db.execute(
        select(DarkWebAlert.severity, func.count())
        .join(DarkWebMonitor, DarkWebAlert.monitor_id == DarkWebMonitor.id)
        .where(DarkWebMonitor.user_id == user_id)
        .where(DarkWebAlert.hidden.is_(False))
        .where(DarkWebMonitor.validation_status == "valid")
        .group_by(DarkWebAlert.severity)
    )).all()
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for sev, n in count_rows:
        if sev in summary:
            summary[sev] = n
    summary["total"] = sum(summary.values())
    return {"alerts": [_alert_to_dict(a, m.target) for a, m in rows], "summary": summary}


async def run_check_and_persist(monitor: DarkWebMonitor, db: AsyncSession) -> tuple[list[DarkWebAlert], dict]:
    """
    Run a dark web check for `monitor`, diff against previously-stored
    alerts and persist only the new ones. Shared by the manual
    POST .../check endpoint and the periodic scheduler
    (modules/darkweb/scheduler.py) so both paths behave identically.

    `last_checked_at` only moves on a successful check
    (modules/darkweb/monitor.check_succeeded); a failed one records
    `last_check_error` instead. Raises InvalidMonitorTarget for a monitor
    flagged invalid. Returns (new_alerts, raw_check_result).
    """
    from modules.darkweb.monitor import run_monitor_check, diff_new_events, check_succeeded

    if (monitor.validation_status or "valid") != "valid":
        raise InvalidMonitorTarget(monitor.validation_error or "invalid target")

    result = await run_monitor_check(monitor.target, monitor.target_type)
    events = result["events"]
    succeeded = check_succeeded(result)
    result["succeeded"] = succeeded

    known = set((await db.execute(
        select(DarkWebAlert.fingerprint).where(DarkWebAlert.monitor_id == monitor.id)
    )).scalars().all())

    new_events = diff_new_events(events, known)
    new_alerts = [
        DarkWebAlert(monitor_id=monitor.id, fingerprint=ev["fingerprint"], source=ev["source"],
                     severity=ev["severity"], title=ev["title"][:300], detail=ev["detail"],
                     matched_field=ev.get("matched_field"), leak_date=ev.get("leak_date"),
                     leaked_fields=ev.get("leaked_fields"))
        for ev in new_events
    ]
    for alert in new_alerts:
        db.add(alert)

    def _apply_status() -> None:
        if succeeded:
            monitor.last_checked_at = datetime.utcnow()
            monitor.last_check_error = None
        else:
            errors = result.get("source_errors") or []
            monitor.last_check_error = "; ".join(e["error"] for e in errors)[:500] or "check failed"

    _apply_status()
    try:
        await db.commit()
    except IntegrityError:
        # A concurrent check (manual + scheduler) stored the same fingerprints
        # first — the unique (monitor_id, fingerprint) index rejected the
        # duplicates. Keep the status update, drop the duplicate alerts.
        await db.rollback()
        _apply_status()
        await db.commit()
        new_alerts = []
    for alert in new_alerts:
        await db.refresh(alert)

    return new_alerts, result


@router.get(
    "/monitor",
    summary="List monitored dark web targets",
    description="List every domain/email currently on the calling user's dark web monitoring watchlist.",
)
async def list_monitors(user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    require_feature_or_402("darkweb_intel", user)
    monitors = (await db.execute(
        select(DarkWebMonitor).where(DarkWebMonitor.user_id == user.id).order_by(DarkWebMonitor.created_at.desc())
    )).scalars().all()
    return JSONResponse({"monitors": [_monitor_to_dict(m) for m in monitors]})


@router.post(
    "/monitor",
    summary="Add a domain/email to dark web monitoring",
    description=(
        "Add `target` (a domain or email, or a username with `target_type: \"username\"`) "
        "to the calling user's dark web watchlist. The target is normalized (lowercase, "
        "scheme/path/port stripped) and validated — a domain must have a TLD; a rejected "
        "target returns 422 with bilingual `message_en`/`message_ar` and a `suggestion` "
        "when one is obvious. Does not run a check itself — call "
        "POST /api/darkweb/monitor/{id}/check afterwards."
    ),
)
async def add_monitor(request: Request, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    require_feature_or_402("darkweb_intel", user)
    data = await request.json()
    from modules.darkweb.targets import validate_target

    v = validate_target(data.get("target"), data.get("target_type") or None)
    if not v.ok:
        return JSONResponse(status_code=422, content={**v.error_payload(),
                                                      "detail": f"{v.error_ar} — {v.error_en}"})
    target, target_type = v.target, v.target_type
    label = (data.get("label") or "").strip() or target

    existing = (await db.execute(
        select(DarkWebMonitor).where(DarkWebMonitor.user_id == user.id, DarkWebMonitor.target == target)
    )).scalar_one_or_none()
    if existing:
        return _bilingual_error(409, "Target is already monitored.", "هذا الهدف مُراقَب بالفعل.")

    monitor = DarkWebMonitor(user_id=user.id, target=target, target_type=target_type, label=label,
                             validation_status="valid")
    db.add(monitor)
    await db.commit()
    await db.refresh(monitor)

    logger.info("darkweb_monitor added user=%s target=%r ip=%s", user.username, target, _client_ip(request))
    return JSONResponse({"success": True, "monitor": _monitor_to_dict(monitor)})


@router.patch(
    "/monitor/{monitor_id}",
    summary="Correct a monitored target",
    description=(
        "Replace a monitor's `target` (re-validated exactly like POST /monitor). "
        "This is how a target flagged invalid becomes checkable again. Alerts "
        "produced by the old target are deleted — they answered a different query."
    ),
)
async def update_monitor(monitor_id: int, request: Request, user: User = Depends(_user),
                         db: AsyncSession = Depends(get_db)):
    require_feature_or_402("darkweb_intel", user)
    monitor = await _get_owned_monitor(monitor_id, user, db)
    data = await request.json()
    from modules.darkweb.targets import validate_target

    v = validate_target(data.get("target"), data.get("target_type") or None)
    if not v.ok:
        return JSONResponse(status_code=422, content={**v.error_payload(),
                                                      "detail": f"{v.error_ar} — {v.error_en}"})
    clash = (await db.execute(
        select(DarkWebMonitor.id).where(DarkWebMonitor.user_id == user.id, DarkWebMonitor.target == v.target,
                                        DarkWebMonitor.id != monitor.id)
    )).scalar_one_or_none()
    if clash:
        return _bilingual_error(409, "Target is already monitored.", "هذا الهدف مُراقَب بالفعل.")

    if v.target != monitor.target or v.target_type != monitor.target_type:
        await db.execute(delete(DarkWebAlert).where(DarkWebAlert.monitor_id == monitor.id))
        if not monitor.label or monitor.label == monitor.target:
            monitor.label = v.target
        monitor.target, monitor.target_type = v.target, v.target_type
        monitor.last_checked_at = None
        monitor.last_check_error = None
    monitor.validation_status = "valid"
    monitor.validation_error = None
    await db.commit()
    await db.refresh(monitor)
    logger.info("darkweb_monitor corrected user=%s monitor_id=%s target=%r", user.username, monitor.id, v.target)
    return JSONResponse({"success": True, "monitor": _monitor_to_dict(monitor)})


@router.delete(
    "/monitor/{monitor_id}",
    summary="Remove a monitored target",
    description="Permanently remove a monitored target and its stored alert history. Only the owning user can delete it.",
)
async def delete_monitor(monitor_id: int, request: Request, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    require_feature_or_402("darkweb_intel", user)
    monitor = await _get_owned_monitor(monitor_id, user, db)
    # Explicit, not just the ORM/FK cascade: the alert feed must never show
    # alerts for a target that no longer exists.
    await db.execute(delete(DarkWebAlert).where(DarkWebAlert.monitor_id == monitor.id))
    await db.delete(monitor)
    await db.commit()
    logger.info("darkweb_monitor deleted user=%s monitor_id=%s ip=%s", user.username, monitor_id, _client_ip(request))
    return JSONResponse({"success": True})


@router.post(
    "/monitor/{monitor_id}/check",
    summary="Run a dark web check for a monitored target",
    description=(
        "Query HIBP, IntelligenceX, BreachDirectory, Leak-Lookup, psbdmp, GitHub, "
        "AlienVault OTX and LeakCheck for the monitored target, diff the results "
        "against previously-stored alerts (deduped by fingerprint), and persist "
        "only the newly-discovered leak events with a discovery timestamp."
    ),
    dependencies=[Depends(_check_monitor_limiter)],
)
async def check_monitor(monitor_id: int, request: Request, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    require_feature_or_402("darkweb_intel", user)
    monitor = await _get_owned_monitor(monitor_id, user, db)

    from modules.darkweb.monitor import build_arabic_alert_message

    if (monitor.validation_status or "valid") != "valid":
        return _bilingual_error(
            409,
            f"This target is invalid and cannot be checked until corrected: {monitor.validation_error or ''}".strip(),
            "هذا الهدف غير صالح ولا يمكن فحصه حتى يتم تصحيحه.",
            monitor=_monitor_to_dict(monitor),
        )

    new_alerts, result = await run_check_and_persist(monitor, db)

    logger.info(
        "darkweb_monitor checked user=%s monitor_id=%s target=%r new_alerts=%d ok=%s ip=%s",
        user.username, monitor.id, monitor.target, len(new_alerts), result.get("succeeded", True), _client_ip(request),
    )

    source_errors = result.get("source_errors") or []
    if not result.get("succeeded", True):
        return _bilingual_error(
            502,
            "The check failed: " + "; ".join(e["error"] for e in source_errors),
            "فشل الفحص: " + "؛ ".join(e["error_ar"] for e in source_errors),
            monitor=_monitor_to_dict(monitor), source_errors=source_errors,
        )

    alert_dicts = [_alert_to_dict(a, monitor.target) for a in new_alerts]
    exposure = result.get("exposure") or {}
    return JSONResponse({
        "success": True,
        "monitor": _monitor_to_dict(monitor),
        "new_alerts": alert_dicts,
        "new_alerts_count": len(alert_dicts),
        "total_events_checked": len(result["events"]),
        "source_errors": source_errors,
        "exposure": exposure,
        "message_ar": build_arabic_alert_message(monitor.target, [
            {"fingerprint": a.fingerprint, "source": a.source, "severity": a.severity, "title": a.title}
            for a in new_alerts
        ]),
    })


@router.get(
    "/monitor/{monitor_id}/alerts",
    summary="List stored alerts for a monitored target",
)
async def list_monitor_alerts(monitor_id: int, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    require_feature_or_402("darkweb_intel", user)
    monitor = await _get_owned_monitor(monitor_id, user, db)
    alerts = (await db.execute(
        select(DarkWebAlert).where(DarkWebAlert.monitor_id == monitor.id, DarkWebAlert.hidden.is_(False))
        .order_by(_SEVERITY_RANK, DarkWebAlert.discovered_at.desc())
    )).scalars().all()
    return JSONResponse({"alerts": [_alert_to_dict(a, monitor.target) for a in alerts]})


@router.get(
    "/monitor/alerts/recent",
    summary="Recent alerts across every monitored target",
    description=(
        "Visible leak alerts across all of the calling user's valid monitored targets, "
        "most severe first then newest, plus a per-severity `summary` count — powers "
        "the dashboard alert panel. Optional `severity` filter and `limit` (max 500)."
    ),
)
async def recent_alerts(severity: str | None = None, limit: int = 100,
                        user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    require_feature_or_402("darkweb_intel", user)
    if severity and severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(400, "severity must be one of critical, high, medium, low")
    return JSONResponse(await visible_alerts_with_summary(user.id, db, limit=max(1, min(limit, 500)),
                                                          severity=severity))


@router.get(
    "/alerts/{alert_id}",
    summary="Masked detail for one alert",
    description=(
        "Matched field (partially masked server-side, e.g. a***@domain.com), source, "
        "leak date and the *names* of the leaked fields. Raw values are never returned."
    ),
)
async def alert_detail(alert_id: int, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    require_feature_or_402("darkweb_intel", user)
    row = (await db.execute(
        _visible_alerts_query(user.id).where(DarkWebAlert.id == alert_id)
    )).first()
    if not row:
        raise HTTPException(404, "alert not found")
    alert, monitor = row
    return JSONResponse(_alert_to_dict(alert, monitor.target))


@router.get(
    "/scheduler/status",
    summary="Dark web monitoring scheduler status",
    description=(
        "Whether the periodic dark web scan sweep (modules/darkweb/scheduler.py) is "
        "running in this process, its configured interval, when it last ran and "
        "what it found, and its next scheduled run."
    ),
)
async def scheduler_status(user: User = Depends(_user)):
    require_feature_or_402("darkweb_intel", user)
    from modules.darkweb.scheduler import get_status
    return JSONResponse(get_status())
