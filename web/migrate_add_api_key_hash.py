"""One-off, idempotent migration: adds User.api_key_hash and retires the
plaintext User.api_key column.

Why this exists: users.api_key used to store the raw, usable-as-a-bearer-
credential API key in plaintext, looked up with a simple equality query
(see web/auth.py get_current_user). A DB dump/leak therefore handed out
every live API key directly. web/auth.py now stores/verifies only a
SHA-256 hash (hash_api_key) -- a fast, unsalted hash is fine here since
generate_api_key() already produces 256 bits of secrets.token_hex entropy,
so there's no offline brute-force risk the way there would be for a
password, and a deterministic hash keeps the same indexed equality lookup.

This project has no Alembic (web/database.py.init_db() only runs
Base.metadata.create_all, which creates missing tables/columns on a fresh
DB but never alters existing ones), so this script issues the DDL/DML
directly. Safe to run multiple times and against either sqlite (dev) or
Postgres (Render): it checks for the target column first and skips
anything already applied.

Steps:
  1. Add users.api_key_hash if missing.
  2. Backfill api_key_hash by hashing any existing plaintext users.api_key
     value (skips rows that have no api_key set).
  3. Best-effort DROP COLUMN users.api_key so the plaintext value stops
     existing at rest. If the running DB/driver can't DROP COLUMN (older
     SQLite, some managed Postgres restrictions), falls back to just
     overwriting every value with NULL -- either way no plaintext key
     survives the migration.

Usage:
    python -m web.migrate_add_api_key_hash
"""

import asyncio
import hashlib

from sqlalchemy import inspect, text

from web.database import engine


def _hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


async def migrate():
    result = {
        "added_column": False,
        "backfilled": 0,
        "dropped_column": False,
        "wiped_to_null": False,
    }

    async with engine.begin() as conn:
        existing_cols = await conn.run_sync(
            lambda sync_conn: {c["name"] for c in inspect(sync_conn).get_columns("users")}
        )

        if "api_key_hash" not in existing_cols:
            await conn.execute(text("ALTER TABLE users ADD COLUMN api_key_hash VARCHAR(64)"))
            print("[migrate] added column users.api_key_hash")
            result["added_column"] = True
        else:
            print("[migrate] column users.api_key_hash already exists — skipping add")

        if "api_key" in existing_cols:
            rows = (await conn.execute(
                text("SELECT id, api_key FROM users WHERE api_key IS NOT NULL")
            )).fetchall()
            for row in rows:
                await conn.execute(
                    text("UPDATE users SET api_key_hash = :h WHERE id = :id"),
                    {"h": _hash_api_key(row.api_key), "id": row.id},
                )
            if rows:
                print(f"[migrate] backfilled api_key_hash for {len(rows)} existing user(s)")
            result["backfilled"] = len(rows)

            try:
                await conn.execute(text("ALTER TABLE users DROP COLUMN api_key"))
                print("[migrate] dropped plaintext column users.api_key")
                result["dropped_column"] = True
            except Exception as exc:
                await conn.execute(text("UPDATE users SET api_key = NULL"))
                print(
                    "[migrate] could not DROP COLUMN users.api_key "
                    f"({exc!r}); wiped its values to NULL instead"
                )
                result["wiped_to_null"] = True
        else:
            print("[migrate] column users.api_key already absent — nothing to backfill/drop")

    return result


if __name__ == "__main__":
    asyncio.run(migrate())
