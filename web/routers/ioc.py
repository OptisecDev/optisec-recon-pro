"""
IOC router — read access to the locally-mined/checked IOC store
(web/models.py::Ioc, modules/ioc/ioc_engine.py). Rows here come from
web/app.py::_extract_and_store_iocs (automatic mining of scan Finding
evidence after every XSS/SQLi/SSRF/LFI/Open Redirect scan) and, in the
future, manual check_ioc()/enrich_ioc() lookups.

Distinct from /correlations (modules/ioc_correlation.py), which correlates
global threat-feed IOCs against each other and never touches this table.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import get_db
from web.models import User, Ioc, Scan, Finding
from web.auth import get_current_user
from modules.ioc.ioc_engine import IOCEngine, IOCRepository, IOC_TYPES

router = APIRouter(prefix="/api/iocs", tags=["ioc"])


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


def _ioc_to_dict(row: Ioc) -> dict:
    return {
        "id": row.id,
        "ioc_type": row.ioc_type,
        "ioc_value": row.ioc_value,
        "source": row.source,
        "confidence_score": row.confidence_score,
        "first_seen": row.first_seen.isoformat() if row.first_seen else None,
        "last_seen": row.last_seen.isoformat() if row.last_seen else None,
        "related_finding_id": row.related_finding_id,
        "tags": row.tags or [],
        "is_active": row.is_active,
    }


@router.get(
    "",
    summary="List detected/stored IOCs",
    description=(
        "List Indicators of Compromise stored locally (mined automatically from scan "
        "Finding evidence, or via manual check_ioc()/enrich_ioc() lookups), newest "
        "last_seen first. Filter by ioc_type (hash_md5/hash_sha256/ip/domain/url/email) "
        "and/or is_active; paginate via limit/offset."
    ),
)
async def list_iocs(
    ioc_type: str | None = None,
    is_active: bool | None = None,
    limit: int = 50,
    offset: int = 0,
    user: User = Depends(_user),
    db: AsyncSession = Depends(get_db),
):
    if ioc_type is not None and ioc_type not in IOC_TYPES:
        return JSONResponse(
            {"error": f"Unsupported ioc_type: {ioc_type!r}, expected one of {sorted(IOC_TYPES)}"},
            status_code=400,
        )

    repo = IOCRepository(db)
    rows = await repo.list_active(ioc_type=ioc_type, is_active=is_active, limit=limit, offset=offset)
    return JSONResponse({
        "iocs": [_ioc_to_dict(r) for r in rows],
        "count": len(rows),
        "limit": max(1, min(limit, 200)),
        "offset": max(0, offset),
    })


@router.get(
    "/search",
    summary="Search stored IOCs by value",
    description=(
        "Substring, case-insensitive search over ioc_value (e.g. a partial domain or "
        "IP) — unlike GET /api/iocs, which only filters by exact ioc_type/is_active. "
        "Optionally narrow by ioc_type."
    ),
)
async def search_iocs(
    q: str,
    ioc_type: str | None = None,
    limit: int = 50,
    user: User = Depends(_user),
    db: AsyncSession = Depends(get_db),
):
    if not (q or "").strip():
        return JSONResponse({"error": "q is required"}, status_code=400)
    if ioc_type is not None and ioc_type not in IOC_TYPES:
        return JSONResponse(
            {"error": f"Unsupported ioc_type: {ioc_type!r}, expected one of {sorted(IOC_TYPES)}"},
            status_code=400,
        )

    repo = IOCRepository(db)
    rows = await repo.search(q.strip(), ioc_type=ioc_type, limit=limit)
    return JSONResponse({"iocs": [_ioc_to_dict(r) for r in rows], "count": len(rows)})


@router.post(
    "/sync",
    summary="Manually trigger an OTX pulse sync",
    description=(
        "Fetch the latest AlienVault OTX pulse indicators and upsert them into the "
        "local IOC store (source=\"otx\"). Runs the same IOCEngine.sync_from_otx() "
        "logic as the periodic background sync (modules/ioc/scheduler.py) — use this "
        "to refresh on demand instead of waiting for the next scheduled sweep."
    ),
)
async def sync_iocs(
    limit: int = 100,
    user: User = Depends(_user),
    db: AsyncSession = Depends(get_db),
):
    engine = IOCEngine(repository=IOCRepository(db))
    summary = await engine.sync_from_otx(limit=limit)
    await db.commit()
    return JSONResponse(summary)


@router.get(
    "/scan/{scan_id}/matches",
    summary="Correlate a scan's findings against the local IOC store",
    description=(
        "For every Finding on the given scan, mine candidate infrastructure IOCs "
        "(same extraction modules/ioc/ioc_engine.py::extract_iocs_from_finding uses) "
        "and check whether any are already known to the local IOC store (e.g. synced "
        "from OTX via POST /api/iocs/sync). Only the scan's owner (or an admin) may "
        "query it."
    ),
)
async def scan_ioc_matches(
    scan_id: str,
    user: User = Depends(_user),
    db: AsyncSession = Depends(get_db),
):
    scan = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "scan not found")
    if scan.user_id != user.id and user.role != "admin":
        raise HTTPException(403, "access denied")

    finding_rows = (await db.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()
    finding_dicts = [
        {"id": f.id, "vuln_type": f.vuln_type, "url": f.url, "evidence": f.evidence or ""}
        for f in finding_rows
    ]

    engine = IOCEngine(repository=IOCRepository(db))
    matches = await engine.match_scan_results(finding_dicts)
    return JSONResponse({"scan_id": scan_id, "matches": matches, "count": len(matches)})


@router.get(
    "/scheduler/status",
    summary="IOC OTX sync scheduler status",
    description=(
        "Whether the periodic OTX pulse sync sweep (modules/ioc/scheduler.py) is "
        "running in this process, its configured interval, when it last ran and "
        "what it found, and its next scheduled run."
    ),
)
async def scheduler_status(user: User = Depends(_user)):
    from modules.ioc.scheduler import get_status
    return JSONResponse(get_status())
