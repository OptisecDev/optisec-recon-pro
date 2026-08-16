"""Shared declarative base and mixins for Eternal Core models."""
import uuid
from datetime import datetime, timezone

from cryptography.fernet import Fernet
from sqlalchemy import DateTime, TypeDecorator, Unicode
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.core.config import FIELD_ENCRYPTION_KEY


class EternalBase(DeclarativeBase):
    pass


class TimestampMixin:
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class EncryptedString(TypeDecorator):
    """Transparently Fernet-encrypts a string column at rest (target PII)."""

    impl = Unicode
    cache_ok = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._fernet = Fernet(FIELD_ENCRYPTION_KEY.encode()) if FIELD_ENCRYPTION_KEY else None

    def process_bind_param(self, value, dialect):
        if value is None or self._fernet is None:
            return value
        return self._fernet.encrypt(value.encode()).decode()

    def process_result_value(self, value, dialect):
        if value is None or self._fernet is None:
            return value
        return self._fernet.decrypt(value.encode()).decode()
