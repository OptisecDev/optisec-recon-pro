"""Configuration for the Eternal Core subsystem, loaded from .env.eternal."""
import os
from pathlib import Path

from cryptography.fernet import Fernet
from dotenv import load_dotenv

_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(_ROOT / ".env.eternal")

ETERNAL_DATABASE_URL = os.getenv(
    "ETERNAL_DATABASE_URL",
    "postgresql+asyncpg://optisec_eternal:optisec_eternal@localhost:5432/optisec_eternal",
)
ETERNAL_DATABASE_URL_SYNC = os.getenv(
    "ETERNAL_DATABASE_URL_SYNC",
    "postgresql+psycopg2://optisec_eternal:optisec_eternal@localhost:5432/optisec_eternal",
)

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ROOT_USER = os.getenv("MINIO_ROOT_USER", "")
MINIO_ROOT_PASSWORD = os.getenv("MINIO_ROOT_PASSWORD", "")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"
MINIO_ARCHIVE_BUCKET = os.getenv("MINIO_ARCHIVE_BUCKET", "optisec-eternal-archive")

ETERNAL_REDIS_URL = os.getenv("ETERNAL_REDIS_URL", "redis://localhost:6379/1")

SECRET_KEY = os.getenv("SECRET_KEY", "")


def _resolve_field_encryption_key() -> str:
    """Fail fast rather than let EncryptedString silently store/return plaintext.

    Eternal Core persists PII (e.g. Target.input_value) in columns declared as
    EncryptedString. There is no acceptable "insecure default" for an at-rest
    encryption key (unlike JWT_SECRET's dev fallback), so any missing or
    malformed key refuses startup outright.
    """
    key = os.getenv("FIELD_ENCRYPTION_KEY", "")
    if not key:
        raise RuntimeError(
            "FIELD_ENCRYPTION_KEY environment variable is not set. Eternal Core "
            "refuses to start: without it, columns declared as EncryptedString "
            "(e.g. Target.input_value) would silently be stored as plaintext. "
            "Set FIELD_ENCRYPTION_KEY in .env.eternal to a valid Fernet key, "
            "e.g. generate one with: python -c \"from cryptography.fernet import "
            "Fernet; print(Fernet.generate_key().decode())\""
        )
    try:
        Fernet(key.encode())
    except Exception as exc:
        raise RuntimeError(
            "FIELD_ENCRYPTION_KEY is set but is not a valid Fernet key "
            f"({exc}). Eternal Core refuses to start: an invalid key would "
            "cause columns declared as EncryptedString to fail encryption "
            "unpredictably. Generate a valid key with: python -c \"from "
            "cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\""
        ) from exc
    return key


FIELD_ENCRYPTION_KEY = _resolve_field_encryption_key()
AUDIT_LOG_ADMIN_PASSWORD = os.getenv("AUDIT_LOG_ADMIN_PASSWORD", "")

ETERNAL_ARCHIVE_AGE_MONTHS = int(os.getenv("ETERNAL_ARCHIVE_AGE_MONTHS", "6"))

# HaveIBeenPwned v3 API key — see README for how to obtain one.
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
