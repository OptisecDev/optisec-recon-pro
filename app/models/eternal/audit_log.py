from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.eternal.base import EternalBase, TimestampMixin


class AuditLog(TimestampMixin, EternalBase):
    __tablename__ = "audit_logs"

    user_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(256), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False)
