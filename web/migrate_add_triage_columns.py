"""One-off, idempotent migration: adds Finding.triage_verdict,
Finding.triage_confidence, and Finding.triage_reason for the AI Triage Engine.

The project has no Alembic (web/database.py.init_db() only runs
Base.metadata.create_all, which creates missing tables but never alters
existing ones), so this script issues the ALTER TABLE statements directly.
Safe to run multiple times and against either sqlite (dev) or Postgres
(docker-compose/Railway) — it checks existing columns first and skips
anything already applied.

Usage:
    python -m web.migrate_add_triage_columns
"""

import asyncio

from sqlalchemy import inspect, text

from web.database import engine

NEW_COLUMNS = {
    "triage_verdict": "VARCHAR(30)",
    "triage_confidence": "FLOAT",
    "triage_reason": "TEXT",
}


async def migrate():
    async with engine.begin() as conn:
        existing_cols = await conn.run_sync(
            lambda sync_conn: {c["name"] for c in inspect(sync_conn).get_columns("findings")}
        )
        for col, coltype in NEW_COLUMNS.items():
            if col in existing_cols:
                print(f"[migrate] column findings.{col} already exists — skipping")
                continue
            await conn.execute(text(f"ALTER TABLE findings ADD COLUMN {col} {coltype}"))
            print(f"[migrate] added column findings.{col} ({coltype})")


if __name__ == "__main__":
    asyncio.run(migrate())
