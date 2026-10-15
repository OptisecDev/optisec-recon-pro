"""Idempotent migration: adds User.token_version (session revocation on
logout -- see web/auth.py get_current_user).

init_db() only runs Base.metadata.create_all, which never adds columns to an
existing table, and every query on User selects this mapped column -- so an
existing database without it would break every login. Like
web/migrate_add_scan_authz_columns.py, this is therefore also run from
web/app.py's startup sequence. That's safe because the column is NOT NULL
with a DEFAULT of 0, so existing rows backfill to 0 -- which matches the
"tv" a token issued before this column existed is treated as having, so
nobody is logged out by the deploy itself.

Safe to run multiple times on sqlite or Postgres.

Usage:
    python -m web.migrate_add_user_token_version
"""

import asyncio

from sqlalchemy import inspect, text

from web.database import engine

COLUMN_NAME = "token_version"
COLUMN_TYPE = "INTEGER NOT NULL DEFAULT 0"


async def migrate() -> bool:
    """Add the column if missing; returns True if it was added."""
    async with engine.begin() as conn:
        existing = await conn.run_sync(
            lambda sync_conn: {c["name"] for c in inspect(sync_conn).get_columns("users")}
        )
        if COLUMN_NAME in existing:
            print(f"[migrate] column users.{COLUMN_NAME} already exists — skipping")
            return False
        await conn.execute(text(f"ALTER TABLE users ADD COLUMN {COLUMN_NAME} {COLUMN_TYPE}"))
    print(f"[migrate] added column users.{COLUMN_NAME} ({COLUMN_TYPE})")
    return True


if __name__ == "__main__":
    asyncio.run(migrate())
