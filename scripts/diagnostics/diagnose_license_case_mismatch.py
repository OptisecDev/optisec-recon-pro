"""Read-only diagnostic: does case-normalization explain redemption failures?

Root cause under test: generate_licenses_admin.py always builds keys from
ALPHABET = string.ascii_uppercase + string.digits (license_utils.py), so
every key_hash stored in license_keys is SHA-256 of an all-uppercase
string. redeem_license() (web/routers/license_routes.py) only .strip()s
the submitted key before hashing -- it never .upper()s it. If the raw key
reaches that endpoint with any lowercase character anywhere (copy/paste
mangling, manual retyping by support, email client auto-formatting), the
resulting hash won't match what's stored, scalar_one_or_none() returns
None, and the endpoint raises the *same* generic 400 as an
already-redeemed key -- with no exception thrown and no traceback logged.

This script is SELECT-only. It never writes to license_keys, never
touches redeemed_by/redeemed_at, and never imports or calls
redeem_license() or any other endpoint logic -- only hash_license_key()
(pure function, no I/O) and a raw read-only SELECT.

Usage (from any directory; the project root is put on sys.path below):

    DATABASE_URL=<production Neon URL> python scripts/diagnostics/diagnose_license_case_mismatch.py \
        "<first failed key as the customer/support supplied it>" \
        "<second failed key>" \
        "<third failed key>"

DATABASE_URL must point at the same database the production app uses --
e.g. run this from a Render shell on the service itself (DATABASE_URL is
already set there), or export the same Neon connection string locally for
the duration of this one read-only check.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sqlalchemy import text  # noqa: E402

from license_utils import hash_license_key  # noqa: E402
from web.database import engine  # noqa: E402


def case_variants(raw_key: str) -> dict[str, str]:
    return {
        "as-submitted": raw_key,
        "stripped": raw_key.strip(),
        "upper": raw_key.strip().upper(),
        "lower": raw_key.strip().lower(),
    }


async def main(raw_keys: list[str]) -> None:
    async with engine.connect() as conn:  # read-only: no .begin(), no commit
        if conn.dialect.name == "postgresql":
            await conn.execute(text("SET TRANSACTION READ ONLY"))
        for raw_key in raw_keys:
            print(f"\n=== Candidate key: {raw_key!r} ===")
            for label, variant in case_variants(raw_key).items():
                h = hash_license_key(variant)
                row = (
                    await conn.execute(
                        text(
                            "SELECT id, tier, redeemed_by, redeemed_at, note "
                            "FROM license_keys WHERE key_hash = :h"
                        ),
                        {"h": h},
                    )
                ).first()
                if row is None:
                    status = "NO MATCH"
                else:
                    status = (
                        f"MATCH -> id={row.id} tier={row.tier} "
                        f"redeemed_by={row.redeemed_by} redeemed_at={row.redeemed_at} "
                        f"note={row.note!r}"
                    )
                print(f"  [{label:12s}] sha256={h}  {status}")
    await engine.dispose()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/diagnostics/diagnose_license_case_mismatch.py <key1> [key2] [key3] ...")
        sys.exit(1)
    asyncio.run(main(sys.argv[1:]))
