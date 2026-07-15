"""One-off, idempotent migration: creates the `license_keys` table
(matching web.models.LicenseKey exactly) and adds users.subscription_tier,
both if not already present.

Why this script exists at all: this project has no Alembic —
web/database.py:init_db() calls Base.metadata.create_all() on every app
startup, which already creates any *missing table* (license_keys included)
the next time the app restarts, on either SQLite or Postgres. It does NOT
alter an *existing* table though, so users.subscription_tier needs an
explicit ADD COLUMN — this script covers both in one idempotent pass,
mirroring web/migrate_add_api_key_hash.py's ALTER TABLE approach and
web/migrate_add_ioc_table.py's checkfirst table-creation approach.

Idempotent and safe to run any number of times, against sqlite (dev) or
Postgres (Render): it checks for the table/column first and only ever
issues CREATE TABLE IF NOT EXISTS / ADD COLUMN IF NOT EXISTS-equivalent
guards — never DROP, never touches existing data.

NOT run automatically from anywhere in this codebase — must be invoked by
hand, same as the other web/migrate_add_*.py scripts.

Usage (local dev):
    python -m web.migrate_add_license_keys

Usage on Render (same runbook as web/migrate_add_ioc_table.py /
scripts/rotate_admin_password.py — connect using the deployment's own
DATABASE_URL, never print anything sensitive):

    DATABASE_URL='postgresql+asyncpg://...' python -m web.migrate_add_license_keys
"""

import asyncio

from sqlalchemy import inspect, text

from web.database import engine
from web.models import LicenseKey

TABLE_NAME = LicenseKey.__tablename__


async def migrate():
    result = {
        "created_table": False,
        "added_column": False,
    }

    async with engine.begin() as conn:
        existing_tables = await conn.run_sync(
            lambda sync_conn: inspect(sync_conn).get_table_names()
        )
        if TABLE_NAME not in existing_tables:
            await conn.run_sync(
                lambda sync_conn: LicenseKey.__table__.create(sync_conn, checkfirst=True)
            )
            print(f"[migrate] created table '{TABLE_NAME}'")
            result["created_table"] = True
        else:
            print(f"[migrate] table '{TABLE_NAME}' already exists — skipping create")

        existing_cols = await conn.run_sync(
            lambda sync_conn: {c["name"] for c in inspect(sync_conn).get_columns("users")}
        )
        if "subscription_tier" not in existing_cols:
            await conn.execute(
                text("ALTER TABLE users ADD COLUMN subscription_tier VARCHAR(20) DEFAULT 'free'")
            )
            print("[migrate] added column users.subscription_tier")
            result["added_column"] = True
        else:
            print("[migrate] column users.subscription_tier already exists — skipping add")

    return result


if __name__ == "__main__":
    asyncio.run(migrate())
