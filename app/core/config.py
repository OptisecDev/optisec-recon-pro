"""Configuration for the Eternal Core subsystem, loaded from .env.eternal."""
import os
from pathlib import Path

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
FIELD_ENCRYPTION_KEY = os.getenv("FIELD_ENCRYPTION_KEY", "")
AUDIT_LOG_ADMIN_PASSWORD = os.getenv("AUDIT_LOG_ADMIN_PASSWORD", "")

ETERNAL_ARCHIVE_AGE_MONTHS = int(os.getenv("ETERNAL_ARCHIVE_AGE_MONTHS", "6"))
