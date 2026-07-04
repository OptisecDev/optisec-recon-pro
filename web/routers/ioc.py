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

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import get_db
from web.models import User, Ioc
from web.auth import get_current_user
from modules.ioc.ioc_engine import IOCRepository, IOC_TYPES

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
