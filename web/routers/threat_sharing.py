"""
Threat Sharing router — export locally-discovered technical IOCs
(honeypot attacker IPs, dark web paste/leak URLs, CISA KEV CVEs) as
STIX/CSV/JSON, receive the community feed, and optionally share a single
IOC with the AlienVault OTX community.

SECURITY / PRIVACY NOTICE — read before enabling ENABLE_THREAT_SHARING:
Sharing is entirely opt-in and OFF by default. Even when enabled, nothing
is ever sent automatically — every share is one explicit POST
/api/threat-feed/share call triggered by a logged-in human. Only technical
indicators (IP / domain / hash / CVE / URL) can ever be shared; see
modules/threat_intel/threat_sharing.py's module docstring and
validate_ioc() for how customer identities and PII are structurally kept
out of both collection and validation.

Query/persistence logic lives in plain functions (record_share,
share_history_to_dicts) rather than inline in the endpoint bodies, mirroring
web/routers/honeypot.py and web/routers/darkweb_monitor.py, so tests can
call them directly against an isolated DB session.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime

from fastapi import APIRouter, Request, Depends, Query
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import get_db
from web.models import User, ThreatShare
from web.auth import get_current_user
from config import OTX_API_KEY, ENABLE_THREAT_SHARING
from modules.threat_intel import threat_sharing as sharing

router = APIRouter(prefix="/api/threat-feed", tags=["threat_sharing"])
logger = logging.getLogger(__name__)


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


def _share_to_dict(row: ThreatShare) -> dict:
    return {
        "id": row.id,
        "ioc_type": row.ioc_type,
        "ioc_value": row.ioc_value,
        "source_module": row.source_module,
        "severity": row.severity,
        "tlp": row.tlp,
        "destination": row.destination,
        "status": row.status,
        "detail": row.detail,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


# ── Persistence (DB logic, unit-testable directly) ─────────────────────────

async def record_share(
    db: AsyncSession, *, user_id: int | None, ioc_type: str, value: str,
    source_module: str, severity: str, tlp: str, result: dict,
) -> ThreatShare:
    row = ThreatShare(
        user_id=user_id,
        ioc_type=ioc_type,
        ioc_value=value,
        source_module=source_module,
        severity=severity,
        tlp=tlp,
        destination="alienvault_otx",
        status=result.get("status", "failed"),
        detail=result,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


async def already_shared_values(db: AsyncSession) -> set[str]:
    rows = (await db.execute(select(ThreatShare.ioc_value).where(ThreatShare.status == "success"))).all()
    return {r[0] for r in rows}


# ── Endpoints ───────────────────────────────────────────────────────────────

@router.get(
    "",
    summary="Global threat feed (received)",
    description="Live IOC feed merging AlienVault OTX pulses (if OTX_API_KEY is configured) with the built-in sample feed — the receiving side of Threat Sharing.",
)
async def get_threat_feed(limit: int = 50, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    from modules.threat_intel.global_feed import get_live_ioc_feed, fetch_real_urlhaus_iocs
    from web.routers.threat_feed import _build_feed

    urlhaus_iocs = await fetch_real_urlhaus_iocs(db, limit=20)
    fallback = get_live_ioc_feed(min(limit, 100), urlhaus_iocs=urlhaus_iocs)
    otx_iocs: list = []
    if OTX_API_KEY:
        try:
            from modules.threat_intel.otx_feed import fetch_otx_pulses
            otx_iocs = await asyncio.to_thread(fetch_otx_pulses, OTX_API_KEY, min(limit, 100))
        except Exception as exc:
            logger.warning("OTX fetch failed, using fallback: %s", exc)

    return JSONResponse(_build_feed(otx_iocs, fallback))


@router.get(
    "/status",
    summary="Threat sharing configuration status",
    description="Whether outbound threat sharing is enabled (ENABLE_THREAT_SHARING) and whether OTX_API_KEY is configured — read this before showing any sharing UI.",
)
async def sharing_status(user: User = Depends(_user)):
    return JSONResponse({
        "enabled": ENABLE_THREAT_SHARING,
        "otx_configured": bool(OTX_API_KEY),
        "message_en": "Threat sharing is enabled." if ENABLE_THREAT_SHARING else
                      "Threat sharing is disabled by default — set ENABLE_THREAT_SHARING=true in .env to enable it.",
        "message_ar": "مشاركة التهديدات مفعّلة." if ENABLE_THREAT_SHARING else
                      "مشاركة التهديدات معطّلة افتراضياً — فعّلها عبر ENABLE_THREAT_SHARING=true في ملف .env",
    })


@router.get(
    "/local-iocs",
    summary="Locally-discovered IOCs eligible for sharing",
    description="Technical IOCs collected from the honeypot (attacker IPs), dark web monitoring (public paste/leak URLs) and CISA KEV (CVEs) — candidates a user can choose to export or manually share.",
)
async def local_iocs(limit: int = 20, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    iocs = await sharing.collect_local_iocs(db, per_source_limit=limit)
    shared = await already_shared_values(db)
    for ioc in iocs:
        ioc["already_shared"] = ioc["value"] in shared
    return JSONResponse({"iocs": iocs, "count": len(iocs), "sharing_enabled": ENABLE_THREAT_SHARING})


@router.get(
    "/export",
    summary="Export locally-discovered IOCs",
    description="Export local IOCs as simplified JSON, CSV, or a minimal STIX 2.1 bundle. This is a read-only export — nothing here is sent anywhere.",
)
async def export_iocs(
    format: str = Query("json", pattern="^(json|csv|stix)$"),
    limit: int = 100,
    user: User = Depends(_user),
    db: AsyncSession = Depends(get_db),
):
    iocs = await sharing.collect_local_iocs(db, per_source_limit=limit)

    if format == "csv":
        return PlainTextResponse(
            sharing.build_csv(iocs), media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=optisec_iocs.csv"},
        )
    if format == "stix":
        return JSONResponse(sharing.build_stix_bundle(iocs))
    return JSONResponse({"iocs": iocs, "count": len(iocs), "exported_at": datetime.utcnow().isoformat()})


@router.get(
    "/history",
    summary="Outbound sharing history (audit trail)",
    description="Every past manual share attempt — success, failure, disabled, or rejected as invalid.",
)
async def share_history(limit: int = 50, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    stmt = select(ThreatShare).order_by(ThreatShare.created_at.desc()).limit(min(limit, 200))
    rows = (await db.execute(stmt)).scalars().all()
    return JSONResponse({"shares": [_share_to_dict(r) for r in rows]})


@router.post(
    "/share",
    summary="Manually share a single IOC with the community",
    description=(
        "Explicit, one-IOC-at-a-time opt-in share to AlienVault OTX. Requires "
        "ENABLE_THREAT_SHARING=true; rejects anything that isn't a valid "
        "IP/domain/hash/CVE/URL (see validate_ioc()). Every attempt — success, "
        "failure, disabled, or invalid — is recorded in the audit trail."
    ),
)
async def share_ioc_endpoint(request: Request, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    data = await request.json()
    ioc_type = (data.get("type") or "").strip().lower()
    value = (data.get("value") or "").strip()
    source_module = data.get("source_module", "manual")
    severity = data.get("severity", "MEDIUM")
    tlp = data.get("tlp", "AMBER")
    description = data.get("description", "")

    result = await sharing.share_ioc(
        ioc_type=ioc_type, value=value, source_module=source_module,
        severity=severity, tlp=tlp, description=description,
    )

    await record_share(
        db, user_id=user.id, ioc_type=ioc_type, value=value,
        source_module=source_module, severity=severity, tlp=tlp, result=result,
    )

    status_code = {"success": 200, "disabled": 403, "invalid": 400, "failed": 502}.get(result["status"], 400)
    return JSONResponse(result, status_code=status_code)
