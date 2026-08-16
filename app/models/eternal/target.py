import enum
import uuid

from sqlalchemy import Enum, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.eternal.base import EncryptedString, EternalBase, TimestampMixin


class TargetInputType(str, enum.Enum):
    EMAIL = "email"
    PHONE = "phone"
    IP = "ip"
    IMAGE = "image"
    PLATE = "plate"


class Target(TimestampMixin, EternalBase):
    __tablename__ = "targets"

    input_type: Mapped[TargetInputType] = mapped_column(
        Enum(TargetInputType, name="target_input_type"), nullable=False
    )
    input_value: Mapped[str] = mapped_column(EncryptedString(512), nullable=False)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), default=uuid.uuid4, index=True, nullable=False
    )
