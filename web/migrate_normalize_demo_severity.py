"""One-off, idempotent data fix: normalizes severity casing on demo-seeded findings.

_ensure_demo_account() in web/app.py used to seed Finding.severity as lowercase
("high"/"critical"/"medium"/"low"), while every real scanner module (via
modules/vuln/waf_aware_classifier.py) writes Title Case ("High"/"Critical"/
"Medium"/"Low"). Accounts with both demo-seeded and real scan findings ended
up with mixed casing in the same findings list/AI analysis. _DEMO_FINDINGS
now seeds Title Case for any *new* demo account, but this backfills existing
rows from a demo account created before that fix — only rows on scans whose
id starts with "demo_" (the demo seeder's own id prefix), so real scan
findings are never touched.

Safe to run multiple times (no-op once already normalized) and against either
sqlite (dev) or Postgres (production) — no schema change, just a data UPDATE.

Usage:
    python -m web.migrate_normalize_demo_severity
"""

import asyncio

from sqlalchemy import text

from web.database import engine

SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


async def migrate() -> dict:
    """Run the backfill and return a dict of {lowercase_severity: rows_updated}."""
    counts = {}
    async with engine.begin() as conn:
        for lower, title in SEVERITY_MAP.items():
            result = await conn.execute(
                text(
                    "UPDATE findings SET severity = :title "
                    "WHERE severity = :lower "
                    "AND scan_id IN (SELECT id FROM scans WHERE id LIKE 'demo\\_%' ESCAPE '\\')"
                ),
                {"title": title, "lower": lower},
            )
            counts[lower] = result.rowcount
            if result.rowcount:
                print(f"[migrate] normalized {result.rowcount} demo finding(s): '{lower}' -> '{title}'")
            else:
                print(f"[migrate] no demo findings with severity='{lower}' — skipping")
    return counts


if __name__ == "__main__":
    asyncio.run(migrate())
