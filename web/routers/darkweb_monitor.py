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
from datetime import datetime, timezone

from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import get_db
from web.models import User, DarkWebMonitor, DarkWebAlert
from web.auth import get_current_user

logger = logging.getLogger("darkweb.monitor.router")
router = APIRouter(prefix="/api/darkweb", tags=["darkweb-monitor"])


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _monitor_to_dict(m: DarkWebMonitor) -> dict:
    return {
        "id": m.id, "target": m.target, "target_type": m.target_type,
        "label": m.label, "is_active": m.is_active,
        "created_at": m.created_at.isoformat() if m.created_at else None,
        "last_checked_at": m.last_checked_at.isoformat() if m.last_checked_at else None,
    }


def _alert_to_dict(a: DarkWebAlert) -> dict:
    from modules.darkweb.monitor import SOURCE_LABELS_AR, SEVERITY_LABELS_AR
    return {
        "id": a.id, "monitor_id": a.monitor_id,
        "source": a.source, "source_ar": SOURCE_LABELS_AR.get(a.source, a.source),
        "severity": a.severity, "severity_ar": SEVERITY_LABELS_AR.get(a.severity, a.severity),
        "title": a.title, "detail": a.detail,
        "discovered_at": a.discovered_at.isoformat() if a.discovered_at else None,
        "acknowledged": a.acknowledged,
    }


async def _get_owned_monitor(monitor_id: int, user: User, db: AsyncSession) -> DarkWebMonitor:
    monitor = (await db.execute(
        select(DarkWebMonitor).where(DarkWebMonitor.id == monitor_id, DarkWebMonitor.user_id == user.id)
    )).scalar_one_or_none()
    if not monitor:
        raise HTTPException(404, "monitor not found")
    return monitor


@router.get(
    "/monitor",
    summary="List monitored dark web targets",
    description="List every domain/email currently on the calling user's dark web monitoring watchlist.",
)
async def list_monitors(user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    monitors = (await db.execute(
        select(DarkWebMonitor).where(DarkWebMonitor.user_id == user.id).order_by(DarkWebMonitor.created_at.desc())
    )).scalars().all()
    return JSONResponse({"monitors": [_monitor_to_dict(m) for m in monitors]})


@router.post(
    "/monitor",
    summary="Add a domain/email to dark web monitoring",
    description=(
        "Add `target` (a domain or email) to the calling user's dark web watchlist. "
        "Detection type (domain vs email) is inferred automatically. Does not run a "
        "check itself — call POST /api/darkweb/monitor/{id}/check afterwards."
    ),
)
async def add_monitor(request: Request, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    data = await request.json()
    target = (data.get("target") or "").strip()
    if not target:
        raise HTTPException(400, "target is required")
    label = (data.get("label") or "").strip() or target

    from modules.osint.darkweb_intelligence import _is_email
    target_type = "email" if _is_email(target) else "domain"

    existing = (await db.execute(
        select(DarkWebMonitor).where(DarkWebMonitor.user_id == user.id, DarkWebMonitor.target == target)
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "target is already monitored")

    monitor = DarkWebMonitor(user_id=user.id, target=target, target_type=target_type, label=label)
    db.add(monitor)
    await db.commit()
    await db.refresh(monitor)

    logger.info("darkweb_monitor added user=%s target=%r ip=%s", user.username, target, _client_ip(request))
    return JSONResponse({"success": True, "monitor": _monitor_to_dict(monitor)})


@router.delete(
    "/monitor/{monitor_id}",
    summary="Remove a monitored target",
    description="Permanently remove a monitored target and its stored alert history. Only the owning user can delete it.",
)
async def delete_monitor(monitor_id: int, request: Request, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    monitor = await _get_owned_monitor(monitor_id, user, db)
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
)
async def check_monitor(monitor_id: int, request: Request, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    monitor = await _get_owned_monitor(monitor_id, user, db)

    from modules.darkweb.monitor import run_monitor_check, diff_new_events, build_arabic_alert_message

    result = await run_monitor_check(monitor.target, monitor.target_type)
    events = result["events"]

    known = set((await db.execute(
        select(DarkWebAlert.fingerprint).where(DarkWebAlert.monitor_id == monitor.id)
    )).scalars().all())

    new_events = diff_new_events(events, known)
    new_alerts = [
        DarkWebAlert(monitor_id=monitor.id, fingerprint=ev["fingerprint"], source=ev["source"],
                      severity=ev["severity"], title=ev["title"], detail=ev["detail"])
        for ev in new_events
    ]
    for alert in new_alerts:
        db.add(alert)

    monitor.last_checked_at = datetime.now(timezone.utc)
    await db.commit()
    for alert in new_alerts:
        await db.refresh(alert)

    logger.info(
        "darkweb_monitor checked user=%s monitor_id=%s target=%r new_alerts=%d ip=%s",
        user.username, monitor.id, monitor.target, len(new_alerts), _client_ip(request),
    )

    alert_dicts = [_alert_to_dict(a) for a in new_alerts]
    exposure = result.get("exposure") or {}
    return JSONResponse({
        "success": True,
        "monitor": _monitor_to_dict(monitor),
        "new_alerts": alert_dicts,
        "new_alerts_count": len(alert_dicts),
        "total_events_checked": len(events),
        "exposure": exposure,
        "message_ar": build_arabic_alert_message(monitor.target, new_events),
    })


@router.get(
    "/monitor/{monitor_id}/alerts",
    summary="List stored alerts for a monitored target",
)
async def list_monitor_alerts(monitor_id: int, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    monitor = await _get_owned_monitor(monitor_id, user, db)
    alerts = (await db.execute(
        select(DarkWebAlert).where(DarkWebAlert.monitor_id == monitor.id).order_by(DarkWebAlert.discovered_at.desc())
    )).scalars().all()
    return JSONResponse({"alerts": [_alert_to_dict(a) for a in alerts]})


@router.get(
    "/monitor/alerts/recent",
    summary="Recent alerts across every monitored target",
    description="The 20 most recent leak alerts across all of the calling user's monitored targets — powers the dashboard alert feed.",
)
async def recent_alerts(user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(
        select(DarkWebAlert, DarkWebMonitor)
        .join(DarkWebMonitor, DarkWebAlert.monitor_id == DarkWebMonitor.id)
        .where(DarkWebMonitor.user_id == user.id)
        .order_by(DarkWebAlert.discovered_at.desc())
        .limit(20)
    )).all()
    alerts = []
    for alert, monitor in rows:
        d = _alert_to_dict(alert)
        d["target"] = monitor.target
        alerts.append(d)
    return JSONResponse({"alerts": alerts})
