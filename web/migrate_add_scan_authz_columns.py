"""Idempotent migration: adds Scan.authz_basis and Scan.authz_checks (why a
scan was allowed to run -- see web/scan_authz.py).

init_db() only runs Base.metadata.create_all, which never adds columns to an
existing table, and every query on Scan selects these mapped columns -- so
an existing database without them would break every scan page. Unlike the
other web/migrate_add_*.py scripts, this one is therefore also run from
web/app.py's startup sequence. That's safe because both columns are
nullable, so the ALTER needs no backfill and old rows simply read as NULL.
Safe to run multiple times on sqlite or Postgres.

Usage:
    python -m web.migrate_add_scan_authz_columns
"""

import asyncio

from sqlalchemy import inspect, text

from web.database import engine

COLUMNS = (
    ("authz_basis", "VARCHAR(300)"),
    ("authz_checks", "JSON"),
)


async def migrate() -> list:
    """Add whichever columns are missing; returns the names added."""
    added = []
    async with engine.begin() as conn:
        existing = await conn.run_sync(
            lambda sync_conn: {c["name"] for c in inspect(sync_conn).get_columns("scans")}
        )
        for name, ddl_type in COLUMNS:
            if name in existing:
                continue
            await conn.execute(text(f"ALTER TABLE scans ADD COLUMN {name} {ddl_type}"))
            added.append(name)
    for name in added:
        print(f"[migrate] added column scans.{name}")
    if not added:
        print("[migrate] scans authz columns already present — skipping")
    return added


if __name__ == "__main__":
    asyncio.run(migrate())
