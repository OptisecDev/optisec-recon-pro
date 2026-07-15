"""Standalone CLI: generate N license keys for sale via SellApp's Unique
Codes delivery, inserting each one's SHA-256 hash into `license_keys`
(web.models.LicenseKey — see web/migrate_add_license_keys.py to create the
table first) and printing the raw keys exactly once. The raw keys are never
stored anywhere — only key_hash is persisted (see license_utils.py) — so
this printed output is the only copy; capture it before closing the
terminal.

Usage:
    python generate_licenses_admin.py --count 50 --tier pro --note "SellApp batch 1"
"""

import argparse
import asyncio
import sys

from web.database import SessionLocal
from web.models import LicenseKey
from license_utils import generate_license_key, hash_license_key


async def generate(count: int, tier: str, note: str) -> list[str]:
    raw_keys = [generate_license_key() for _ in range(count)]

    async with SessionLocal() as db:
        for raw_key in raw_keys:
            db.add(LicenseKey(
                key_hash=hash_license_key(raw_key),
                tier=tier,
                note=note or None,
            ))
        await db.commit()

    return raw_keys


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate OPTISEC license keys for sale")
    parser.add_argument("--count", type=int, required=True, help="Number of keys to generate")
    parser.add_argument("--tier", default="pro", help="Tier to grant on redemption (default: pro)")
    parser.add_argument("--note", default="", help="Optional note stored alongside each key")
    args = parser.parse_args()

    if args.count < 1:
        print("[OPTISEC] Error: --count must be at least 1", file=sys.stderr)
        sys.exit(1)

    raw_keys = asyncio.run(generate(args.count, args.tier, args.note))

    print(f"[OPTISEC] Generated {len(raw_keys)} license key(s), tier={args.tier!r}")
    print("[OPTISEC] Raw keys (shown once — copy these now for SellApp upload):")
    for key in raw_keys:
        print(key)


if __name__ == "__main__":
    main()
