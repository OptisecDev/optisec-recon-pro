"""One-off, idempotent migration for dark web target validation + alert rework.

1. Adds DarkWebMonitor.validation_status / validation_error / last_check_error
   and DarkWebAlert.matched_field / leak_date / leaked_fields / hidden.
2. Re-validates every existing monitor with modules/darkweb/targets.py — a
   target that fails (e.g. a domain without a TLD such as "tp-link") is
   flagged `invalid`, its alerts are hidden, and it is never checked until
   the user corrects it. Valid targets are rewritten in normalized form when
   that doesn't collide with another monitor of the same user.
3. Upgrades legacy LeakCheck alerts (fingerprint = source name only, flat
   "high" severity) to the new (source + matched field + target) fingerprint
   and the real severity model, so the next check doesn't re-alert them.
4. Deletes orphan alerts (monitor row gone) and duplicate fingerprints, then
   adds a unique (monitor_id, fingerprint) index.

The project has no Alembic for web/ (init_db() only creates missing tables),
so this issues ALTER TABLE directly, like the other web/migrate_*.py scripts.
Safe to run repeatedly against sqlite or Postgres.

Usage:
    python -m web.migrate_darkweb_target_validation [--dry-run]
"""

import asyncio
import sys

from sqlalchemy import inspect, text

from web.database import engine

MONITOR_COLUMNS = {
    "validation_status": "VARCHAR(20) NOT NULL DEFAULT 'valid'",
    "validation_error": "VARCHAR(500)",
    "last_check_error": "VARCHAR(500)",
}
ALERT_COLUMNS = {
    "matched_field": "VARCHAR(20)",
    "leak_date": "VARCHAR(20)",
    "leaked_fields": "JSON",
    "hidden": "BOOLEAN NOT NULL DEFAULT FALSE",
}


def _legacy_leakcheck_upgrade(detail: dict, target: str, target_type: str) -> dict | None:
    """New-shape fields for a pre-rework LeakCheck alert, or None if the row
    isn't one (already upgraded, or a different source)."""
    from modules.darkweb.leak_records import record_to_event
    if not isinstance(detail, dict) or "source_name" not in detail or "matched_field" in detail:
        return None
    ev = record_to_event({
        "provider": "leakcheck", "source_name": detail.get("source_name"), "leak_date": None,
        "matched_field": target_type, "matched_value": target,
        "leaked_fields": detail.get("fields") or [],
    }, target, target_type)
    return ev


async def migrate(dry_run: bool = False) -> dict:
    import json
    from modules.darkweb.targets import validate_target

    report = {"columns_added": [], "invalid": [], "normalized": [], "upgraded_alerts": 0,
              "hidden_alerts": 0, "orphans_deleted": 0, "duplicates_deleted": 0}

    async with engine.begin() as conn:
        def _cols(sync_conn, table):
            return {c["name"] for c in inspect(sync_conn).get_columns(table)}

        for table, cols in (("darkweb_monitors", MONITOR_COLUMNS), ("darkweb_alerts", ALERT_COLUMNS)):
            existing = await conn.run_sync(_cols, table)
            for col, coltype in cols.items():
                if col not in existing:
                    report["columns_added"].append(f"{table}.{col}")
                    if not dry_run:
                        await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {coltype}"))

        if dry_run and report["columns_added"]:
            # Can't read the new columns before they exist; report what would change.
            monitors = (await conn.execute(text(
                "SELECT id, user_id, target, target_type FROM darkweb_monitors"))).all()
            for mid, _uid, target, ttype in monitors:
                v = validate_target(target, ttype if ttype in ("domain", "email", "username") else None)
                if not v.ok:
                    report["invalid"].append({"id": mid, "target": target, "suggestion": v.suggestion})
            return report

        # Orphans first (FK cascade normally prevents them, but sqlite without
        # PRAGMA foreign_keys and manual deletes don't honour it).
        res = await conn.execute(text(
            "DELETE FROM darkweb_alerts WHERE monitor_id NOT IN (SELECT id FROM darkweb_monitors)"))
        report["orphans_deleted"] = res.rowcount or 0

        monitors = (await conn.execute(text(
            "SELECT id, user_id, target, target_type, validation_status FROM darkweb_monitors"))).all()
        taken = {(uid, target) for _id, uid, target, _t, _s in monitors}
        for mid, uid, target, ttype, status in monitors:
            v = validate_target(target, ttype if ttype in ("domain", "email", "username") else None)
            if not v.ok:
                if status != "invalid":
                    await conn.execute(text(
                        "UPDATE darkweb_monitors SET validation_status='invalid', validation_error=:e WHERE id=:id"),
                        {"e": f"{v.error_en} / {v.error_ar}"[:500], "id": mid})
                res = await conn.execute(text(
                    "UPDATE darkweb_alerts SET hidden=:t WHERE monitor_id=:id AND hidden=:f"),
                    {"id": mid, "t": True, "f": False})
                report["hidden_alerts"] += res.rowcount or 0
                report["invalid"].append({"id": mid, "target": target, "suggestion": v.suggestion})
                continue
            if v.target != target and (uid, v.target) not in taken:
                await conn.execute(text(
                    "UPDATE darkweb_monitors SET target=:t, target_type=:tt WHERE id=:id"),
                    {"t": v.target, "tt": v.target_type, "id": mid})
                taken.add((uid, v.target))
                report["normalized"].append({"id": mid, "from": target, "to": v.target})
                target = v.target
            if ttype != v.target_type:
                await conn.execute(text("UPDATE darkweb_monitors SET target_type=:tt WHERE id=:id"),
                                   {"tt": v.target_type, "id": mid})

            alerts = (await conn.execute(text(
                "SELECT id, detail FROM darkweb_alerts WHERE monitor_id=:id AND source='leakcheck'"),
                {"id": mid})).all()
            for aid, detail in alerts:
                if isinstance(detail, str):
                    try:
                        detail = json.loads(detail)
                    except ValueError:
                        continue
                ev = _legacy_leakcheck_upgrade(detail, target, v.target_type)
                if not ev:
                    continue
                await conn.execute(text(
                    "UPDATE darkweb_alerts SET fingerprint=:fp, severity=:sev, title=:title, detail=:detail, "
                    "matched_field=:mf, leak_date=:ld, leaked_fields=:lf WHERE id=:id"),
                    {"fp": ev["fingerprint"], "sev": ev["severity"], "title": ev["title"][:300],
                     "detail": json.dumps(ev["detail"]), "mf": ev["matched_field"], "ld": ev["leak_date"],
                     "lf": json.dumps(ev["leaked_fields"]), "id": aid})
                report["upgraded_alerts"] += 1

        res = await conn.execute(text(
            "DELETE FROM darkweb_alerts WHERE id NOT IN ("
            "  SELECT keep_id FROM (SELECT MIN(id) AS keep_id FROM darkweb_alerts"
            "  GROUP BY monitor_id, fingerprint) AS k)"))
        report["duplicates_deleted"] = res.rowcount or 0
        await conn.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_darkweb_alerts_monitor_fp "
            "ON darkweb_alerts (monitor_id, fingerprint)"))

    return report


if __name__ == "__main__":
    result = asyncio.run(migrate(dry_run="--dry-run" in sys.argv))
    for key, value in result.items():
        print(f"[migrate] {key}: {value}")
