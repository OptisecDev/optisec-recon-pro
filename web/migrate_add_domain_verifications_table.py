"""One-off, idempotent migration: creates the domain_verifications table
(web/models.py DomainVerification) used by scan authorization.

init_db() already runs Base.metadata.create_all on startup, which creates
missing tables, so a normal deploy picks this table up on its own. This
script exists to create it ahead of a deploy, or against a database the app
hasn't started on yet, without running the rest of the startup sequence.
Safe to run multiple times on sqlite or Postgres (checkfirst=True).

Usage:
    python -m web.migrate_add_domain_verifications_table
"""

import asyncio

from sqlalchemy import inspect

from web.database import Base, engine
from web import models  # noqa: F401 -- registers models with Base metadata

TABLE_NAME = "domain_verifications"


async def migrate():
    async with engine.begin() as conn:
        exists = await conn.run_sync(lambda sync_conn: inspect(sync_conn).has_table(TABLE_NAME))
        if exists:
            print(f"[migrate] table {TABLE_NAME} already exists — skipping")
            return
        await conn.run_sync(lambda sync_conn: Base.metadata.tables[TABLE_NAME].create(sync_conn, checkfirst=True))
        print(f"[migrate] created table {TABLE_NAME}")


if __name__ == "__main__":
    asyncio.run(migrate())
