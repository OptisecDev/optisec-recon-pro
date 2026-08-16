import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.eternal.base import EternalBase, TimestampMixin


class ReconArtifact(TimestampMixin, EternalBase):
    """SCD Type 2: a row is the current version of a fact while valid_to is NULL."""

    __tablename__ = "recon_artifacts"

    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id"), index=True, nullable=False
    )
    source_type: Mapped[str] = mapped_column(String(128), nullable=False)
    raw_data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    valid_to: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
