"""One-off, idempotent migration: creates the `auth_events` table (matching
web.models.AuthEvent exactly) if it does not already exist.

Why this script exists at all: this project has no Alembic —
web/database.py:init_db() calls Base.metadata.create_all() on every app
startup, which *already* creates any table that's missing, `auth_events`
included (see web/migrate_add_ioc_table.py for the same pattern on an
earlier table). That happens automatically the next time the app restarts,
on either SQLite or Postgres. This script is an explicit, reviewable
alternative for anyone who wants to create the table ahead of a deploy, or
independently of an app-boot side effect — the DDL here is generated
directly from AuthEvent.__table__ instead of hand-written SQL, so the
schema is guaranteed to match the model column-for-column, index-for-index,
constraint-for-constraint.

Idempotent and safe to run any number of times, against sqlite (dev) or
Postgres (Render): it checks for the table first and only ever issues
CREATE TABLE — never DROP, never ALTER, never touches an existing
`auth_events` table's data or schema.

NOT run automatically from anywhere in this codebase. web/app.py's startup
handler calls only init_db() (create_all across *all* models) — it never
imports or calls this script, and nothing else does either. It must be
invoked by hand.

Manual usage on Render (same pattern as scripts/rotate_admin_password.py /
SECURITY.md's password-rotation runbook: connect using the deployment's own
DATABASE_URL, never print anything sensitive):

    Option 1 — Render Shell tab (if your plan has one), DATABASE_URL is
    already set in that environment:

        python -m web.migrate_add_auth_events_table

    Option 2 — from any machine, using Render's Postgres "External Database
    URL" (Render dashboard -> your Postgres instance), exported only for
    this one command and not persisted to shell history or a committed
    .env file:

        DATABASE_URL='postgresql+asyncpg://...' python -m web.migrate_add_auth_events_table

This script only ever prints table/column/index/constraint *names* — never
row data, connection strings, or credentials.

Usage (local dev):
    python -m web.migrate_add_auth_events_table
"""

import asyncio

from sqlalchemy import inspect

from web.database import engine
from web.models import AuthEvent

TABLE_NAME = AuthEvent.__tablename__


async def migrate():
    columns = [c.name for c in AuthEvent.__table__.columns]
    indexes = sorted(ix.name for ix in AuthEvent.__table__.indexes)
    constraints = sorted(
        c.name for c in AuthEvent.__table__.constraints if getattr(c, "name", None)
    )

    async with engine.begin() as conn:
        existing_tables = await conn.run_sync(
            lambda sync_conn: inspect(sync_conn).get_table_names()
        )
        if TABLE_NAME in existing_tables:
            print(f"[migrate] الجدول '{TABLE_NAME}' موجود مسبقاً — لا تغيير")
            return {
                "created": False,
                "table": TABLE_NAME,
                "columns": columns,
                "indexes": indexes,
                "constraints": constraints,
            }

        await conn.run_sync(lambda sync_conn: AuthEvent.__table__.create(sync_conn, checkfirst=True))

    print(f"[migrate] تم إنشاء الجدول '{TABLE_NAME}'")
    print(f"[migrate] الأعمدة ({len(columns)}): {', '.join(columns)}")
    print(f"[migrate] الفهارس (indexes) ({len(indexes)}): {', '.join(indexes) if indexes else '(لا يوجد)'}")
    print(f"[migrate] القيود (constraints) ({len(constraints)}): {', '.join(constraints) if constraints else '(لا يوجد اسم صريح)'}")
    return {
        "created": True,
        "table": TABLE_NAME,
        "columns": columns,
        "indexes": indexes,
        "constraints": constraints,
    }


if __name__ == "__main__":
    asyncio.run(migrate())
