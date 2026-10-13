"""One-off, idempotent migration: creates the `ai_blocked_logs` table (matching
modules.ai_middleware.AIBlockedLog exactly) if it does not already exist.

Unlike the other web/migrate_add_*_table.py scripts, this table is NOT created
by web/database.py:init_db() at startup: AIBlockedLog is declared on its own
metadata (modules.ai_middleware.AuditBase), not on web.database.Base, on
purpose, so that adding the AI middleware applies no schema change to any
database until an operator decides to. This script is the only thing that
creates the table.

The table is an audit log only. Every row has action = 'flagged' (enforced by
a CHECK constraint); nothing reads it to block traffic.

Idempotent and safe to run any number of times, against sqlite (dev) or
Postgres: it checks for the table first and only ever issues CREATE TABLE —
never DROP, never ALTER, never touches existing rows.

NOT run automatically from anywhere in this codebase. It must be invoked by
hand, using the deployment's own DATABASE_URL (never printed):

    python -m web.migrate_add_ai_blocked_logs_table

This script only ever prints table/column/index/constraint *names*.
"""

import asyncio

from sqlalchemy import inspect

from web.database import engine
from modules.ai_middleware import AIBlockedLog

TABLE_NAME = AIBlockedLog.__tablename__


async def migrate():
    columns = [c.name for c in AIBlockedLog.__table__.columns]
    indexes = sorted(ix.name for ix in AIBlockedLog.__table__.indexes)
    constraints = sorted(
        c.name for c in AIBlockedLog.__table__.constraints if getattr(c, "name", None)
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

        await conn.run_sync(lambda sync_conn: AIBlockedLog.__table__.create(sync_conn, checkfirst=True))

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
