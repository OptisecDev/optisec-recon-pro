"""
Honeypot router — lightweight SSH/FTP/HTTP-admin decoy listeners
(modules/honeypot/listeners.py, modules/honeypot/manager.py) that capture
and enrich attacker connection attempts (modules/honeypot/enrichment.py)
into the HoneypotEvent table.

Query/aggregation logic lives here as plain functions (query_events,
compute_stats) rather than inline in the endpoint bodies, mirroring
web/routers/darkweb_monitor.py's run_check_and_persist — so tests can call
them directly against an isolated DB session without going through HTTP.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import get_db
from web.models import User, HoneypotEvent
from web.auth import get_current_user
from web.shared_templates import templates
from config import APP_NAME
from modules.honeypot import listeners

router = APIRouter(prefix="/api/honeypot", tags=["honeypot"])
page_router = APIRouter(tags=["honeypot"])

VALID_SERVICES = frozenset(listeners.HANDLERS.keys())
VALID_RISK_LEVELS = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"})


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


def _event_to_dict(e: HoneypotEvent) -> dict:
    return {
        "id": e.id, "service": e.service, "service_ar": listeners.SERVICE_LABELS_AR.get(e.service, e.service),
        "source_ip": e.source_ip, "source_port": e.source_port, "dest_port": e.dest_port,
        "payload": e.payload, "session_data": e.session_data,
        "country": e.country, "country_code": e.country_code, "city": e.city, "isp": e.isp,
        "abuse_score": e.abuse_score, "risk_level": e.risk_level,
        "created_at": e.created_at.isoformat() if e.created_at else None,
    }


# ── Query / aggregation (DB logic, unit-testable directly) ──────────────

async def query_events(db: AsyncSession, *, service: str | None = None, source_ip: str | None = None,
                        risk_level: str | None = None, since: datetime | None = None,
                        limit: int = 50, offset: int = 0) -> list[HoneypotEvent]:
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    stmt = select(HoneypotEvent)
    if service:
        stmt = stmt.where(HoneypotEvent.service == service)
    if source_ip:
        stmt = stmt.where(HoneypotEvent.source_ip == source_ip)
    if risk_level:
        stmt = stmt.where(HoneypotEvent.risk_level == risk_level.upper())
    if since:
        stmt = stmt.where(HoneypotEvent.created_at >= since)
    stmt = stmt.order_by(HoneypotEvent.created_at.desc()).limit(limit).offset(offset)

    return list((await db.execute(stmt)).scalars().all())


def build_heatmap(timestamps: list[datetime]) -> list[dict]:
    """7x24 grid of event counts by (weekday, hour) — weekday 0=Monday per
    datetime.weekday(). Pure function, no DB/network dependency, so it's
    portable across SQLite/Postgres without relying on DB-specific date
    functions."""
    grid = [[0] * 24 for _ in range(7)]
    for ts in timestamps:
        if ts is None:
            continue
        grid[ts.weekday()][ts.hour] += 1
    return [{"weekday": wd, "hour": h, "count": grid[wd][h]} for wd in range(7) for h in range(24)]


async def compute_stats(db: AsyncSession) -> dict:
    total = (await db.execute(select(func.count()).select_from(HoneypotEvent))).scalar() or 0

    by_service = dict((await db.execute(
        select(HoneypotEvent.service, func.count()).group_by(HoneypotEvent.service)
    )).all())

    by_risk = dict((await db.execute(
        select(HoneypotEvent.risk_level, func.count()).group_by(HoneypotEvent.risk_level)
    )).all())

    top_ip_rows = (await db.execute(
        select(HoneypotEvent.source_ip, func.count().label("hits"))
        .group_by(HoneypotEvent.source_ip)
        .order_by(func.count().desc())
        .limit(10)
    )).all()
    top_ips = [{"ip": ip, "hits": hits} for ip, hits in top_ip_rows]

    top_country_rows = (await db.execute(
        select(HoneypotEvent.country, func.count().label("hits"))
        .where(HoneypotEvent.country.isnot(None))
        .group_by(HoneypotEvent.country)
        .order_by(func.count().desc())
        .limit(10)
    )).all()
    top_countries = [{"country": c, "hits": hits} for c, hits in top_country_rows]

    since = datetime.utcnow() - timedelta(days=7)
    recent_timestamps = list((await db.execute(
        select(HoneypotEvent.created_at).where(HoneypotEvent.created_at >= since)
    )).scalars().all())

    return {
        "total_events": total,
        "by_service": by_service,
        "by_service_ar": {s: listeners.SERVICE_LABELS_AR.get(s, s) for s in by_service},
        "by_risk_level": by_risk,
        "top_attacker_ips": top_ips,
        "top_countries": top_countries,
        "heatmap_7d": build_heatmap(recent_timestamps),
        "events_last_7d": len(recent_timestamps),
        "generated_at": datetime.utcnow().isoformat(),
    }


# ── API endpoints ─────────────────────────────────────────────────────────

@router.get(
    "/events",
    summary="List captured honeypot events",
    description=(
        "List connection attempts captured by the SSH/FTP/HTTP-admin honeypot listeners, "
        "newest first. Filter by service, source IP, or risk level; paginate via limit/offset."
    ),
)
async def list_events(
    request: Request,
    service: str | None = None,
    source_ip: str | None = None,
    risk_level: str | None = None,
    hours: int | None = None,
    limit: int = 50,
    offset: int = 0,
    user: User = Depends(_user),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.utcnow() - timedelta(hours=hours) if hours else None
    events = await query_events(
        db, service=service, source_ip=source_ip, risk_level=risk_level,
        since=since, limit=limit, offset=offset,
    )
    return JSONResponse({"events": [_event_to_dict(e) for e in events], "count": len(events)})


@router.get(
    "/stats",
    summary="Honeypot statistics",
    description="Aggregated honeypot stats: totals by service/risk level, top attacker IPs/countries, and a 7-day activity heatmap for the dashboard.",
)
async def stats(user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    return JSONResponse(await compute_stats(db))


@router.get(
    "/status",
    summary="Honeypot listener status",
    description="Whether the honeypot subsystem is enabled and which of the SSH/FTP/HTTP-admin listeners are currently bound.",
)
async def status(user: User = Depends(_user)):
    from modules.honeypot.manager import get_status
    return JSONResponse(get_status())


# ── Dashboard page ────────────────────────────────────────────────────────

@page_router.get("/honeypot", response_class=HTMLResponse)
async def honeypot_page(request: Request, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    from modules.honeypot.manager import get_status

    recent_events = await query_events(db, limit=50)
    page_stats = await compute_stats(db)

    return templates.TemplateResponse(request, "honeypot.html", {
        "app_name": APP_NAME, "user": user, "active": "honeypot",
        "events": [_event_to_dict(e) for e in recent_events],
        "stats": page_stats,
        "manager_status": get_status(),
    })
