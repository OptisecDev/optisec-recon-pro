"""One-off, idempotent migration: adds Finding.include_in_report.

Context: the WAF-aware classifier (modules/vuln/waf_aware_classifier.py)
produces five possible verdicts (CONFIRMED/WAF_BLOCKED/ENDPOINT_INVALID/
ENCODED_SAFE/INCONCLUSIVE) per test. Previously only CONFIRMED results were
saved as Finding rows at all — everything else was discarded before it ever
reached the database. As of this migration, every verdict is persisted (kept
as evidence/intelligence, e.g. for bug-bounty write-ups showing a WAF was
actively probed), and include_in_report is the flag that reproduces the old
CONFIRMED-only behavior for anything client-facing (dashboard counts, PDF
report, /api/findings).

The project has no Alembic (web/database.py.init_db() only runs
Base.metadata.create_all, which creates missing tables but never alters
existing ones), so this script issues the ALTER TABLE statement directly.
Safe to run multiple times and against either sqlite (dev) or Postgres
(docker-compose/Railway/Render) — it checks the existing column first and
skips if already applied. `BOOLEAN ... DEFAULT TRUE` is valid syntax on both
dialects (SQLite has understood the TRUE/FALSE keywords as 1/0 since 3.23),
so no dialect branching is needed. Existing rows all backfill to TRUE, which
is correct: every Finding already in the table today is a CONFIRMED result
that was already being shown to clients.

Usage:
    python -m web.migrate_add_finding_include_in_report_column
"""

import asyncio

from sqlalchemy import inspect, text

from web.database import engine

COLUMN_NAME = "include_in_report"
COLUMN_TYPE = "BOOLEAN NOT NULL DEFAULT TRUE"


async def migrate():
    async with engine.begin() as conn:
        existing_cols = await conn.run_sync(
            lambda sync_conn: {c["name"] for c in inspect(sync_conn).get_columns("findings")}
        )
        if COLUMN_NAME in existing_cols:
            print(f"[migrate] column findings.{COLUMN_NAME} already exists — skipping")
            return
        await conn.execute(text(f"ALTER TABLE findings ADD COLUMN {COLUMN_NAME} {COLUMN_TYPE}"))
        print(f"[migrate] added column findings.{COLUMN_NAME} ({COLUMN_TYPE})")


if __name__ == "__main__":
    asyncio.run(migrate())
