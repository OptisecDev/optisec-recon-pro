import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models.eternal.target import TargetInputType


class ScanRequest(BaseModel):
    type: TargetInputType
    value: str


class ScanResponse(BaseModel):
    target_id: uuid.UUID
    session_id: uuid.UUID
    result: dict


class TimelineEntry(BaseModel):
    id: str
    target_id: str
    source_type: str
    raw_data: dict
    created_at: str
    valid_to: str | None
    storage: str


class SimulationStepResponse(BaseModel):
    step_order: int
    mitre_tactic: str
    description: str
    executed_at: str
    simulated: bool
    note: str
    note_ar: str


class AuditLogEntry(BaseModel):
    id: uuid.UUID
    user_id: str
    action: str
    ip_address: str
    created_at: datetime

    class Config:
        from_attributes = True
