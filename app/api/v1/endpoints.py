import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.schemas import (
    AuditLogEntry,
    ScanRequest,
    ScanResponse,
    SimulationStepResponse,
    TimelineEntry,
)
from app.core.config import AUDIT_LOG_ADMIN_PASSWORD
from app.core.rate_limit import enforce_rate_limit
from app.db.session import get_eternal_db
from app.models.eternal.audit_log import AuditLog
from app.models.eternal.recon_artifact import ReconArtifact
from app.models.eternal.target import Target, TargetInputType
from app.services.recon.recon_engine import scan_email, simulate_attack_chain
from app.services.storage.hybrid_repository import query_timeline, save_active

router = APIRouter()
_security = HTTPBasic()


def _require_admin(credentials: HTTPBasicCredentials = Depends(_security)) -> str:
    """Shared auth gate for every Eternal Core v1 endpoint.

    Eternal Core has no per-user account system of its own (no signup, no
    session/cookie auth) -- AUDIT_LOG_ADMIN_PASSWORD is the one operator
    secret this subsystem defines, originally wired only to /audit/logs.
    scan/history/simulate previously had no auth at all, so this is reused
    here rather than inventing a second secret/env var.
    """
    valid = AUDIT_LOG_ADMIN_PASSWORD and secrets.compare_digest(
        credentials.password, AUDIT_LOG_ADMIN_PASSWORD
    )
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid audit credentials")
    return credentials.username


async def _log_action(db: AsyncSession, request: Request, action: str, user_id: str = "system"):
    db.add(
        AuditLog(
            user_id=user_id,
            action=action,
            ip_address=request.client.host if request.client else "unknown",
        )
    )
    await db.commit()


@router.post("/scan", response_model=ScanResponse)
async def run_scan(
    payload: ScanRequest,
    request: Request,
    db: AsyncSession = Depends(get_eternal_db),
    _rate: None = Depends(enforce_rate_limit),
    _admin: str = Depends(_require_admin),
):
    session_id = uuid.uuid4()
    target = Target(input_type=payload.type, input_value=payload.value, session_id=session_id)
    db.add(target)
    await db.flush()

    if payload.type == TargetInputType.EMAIL:
        result = await scan_email(payload.value)
        source_type = result.get("source", "mock_fallback")
    else:
        result = {
            "note": f"Mock recon engine has no live source for type={payload.type.value} yet.",
            "type": payload.type.value,
            "value_received": True,
            "mock": True,
            "source": "mock_fallback",
        }
        source_type = "mock_fallback"

    artifact = ReconArtifact(target_id=target.id, source_type=source_type, raw_data=result)
    await save_active(artifact, db)

    action = f"scan:{payload.type.value}"
    if source_type == "mock_fallback" and payload.type == TargetInputType.EMAIL:
        action += ":hibp_fallback_warning"
    await _log_action(db, request, action=action)

    return ScanResponse(target_id=target.id, session_id=session_id, result=result)


@router.get("/history/{target_id}", response_model=list[TimelineEntry])
async def get_history(
    target_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_eternal_db),
    _rate: None = Depends(enforce_rate_limit),
    _admin: str = Depends(_require_admin),
):
    timeline = await query_timeline(target_id, db)
    await _log_action(db, request, action=f"history:{target_id}")
    return timeline


@router.post("/simulate/{target_id}", response_model=list[SimulationStepResponse])
async def run_simulation(
    target_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_eternal_db),
    _rate: None = Depends(enforce_rate_limit),
    _admin: str = Depends(_require_admin),
):
    target = await db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    steps = await simulate_attack_chain(target_id)
    await _log_action(db, request, action=f"simulate:{target_id}")
    return steps


@router.get("/audit/logs", response_model=list[AuditLogEntry])
async def get_audit_logs(
    db: AsyncSession = Depends(get_eternal_db),
    _rate: None = Depends(enforce_rate_limit),
    _admin: str = Depends(_require_admin),
):
    result = await db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()))
    return result.scalars().all()
