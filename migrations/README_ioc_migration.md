# IOC Detection — `iocs` table migration plan

Status: **applied to production**. On 2026-07-04 `web/migrate_add_ioc_table.py`
was run against the Render production database via a temporary token-gated
endpoint (`POST /internal/run-ioc-migration` in `web/app.py`), which returned
`{"success": true, "table": "iocs", ...}`. The `iocs` table is confirmed to
exist on the production database. That endpoint (and its diagnostic logging)
was purely a one-off deployment tool and has since been deleted from
`web/app.py` — it is not part of the application. `web/migrate_add_ioc_table.py`
itself remains in the codebase as the standalone, reusable migration script
(see "Run `web/migrate_add_ioc_table.py` manually" below) in case it ever
needs to be re-run against another database (e.g. a fresh environment).

## Why this is *not* like the previous `web/migrate_add_finding_*.py` scripts

This project has no Alembic. `web/database.py:init_db()` calls
`Base.metadata.create_all(...)`, which:

- **creates any table that doesn't exist yet** — this is why past features
  that added a brand-new table (`DarkWebMonitor`, `HoneypotEvent`,
  `ThreatShare`, `CveDraft`, ...) never needed a migration script at all.
- **never alters an existing table** — this is why `waf_detected`/`verdict`
  on `Finding` (an existing table) needed
  `web/migrate_add_finding_waf_columns.py` with explicit `ALTER TABLE`.

`iocs` is a brand-new table, not a new column on an existing one, so
`init_db()` (running on the next app startup, local or Render) would create
it automatically as a side effect of booting the app. Rather than rely on
that implicit boot side effect, this table is created via an **explicit,
reviewable migration script** — `web/migrate_add_ioc_table.py` — matching
the pattern already established by `web/migrate_add_finding_waf_columns.py`
and `web/migrate_add_finding_include_in_report_column.py`, except it builds
the `CREATE TABLE` directly from `Ioc.__table__` (via
`Ioc.__table__.create()`) instead of raw SQL, so the schema is guaranteed to
match the model exactly.

## Run `web/migrate_add_ioc_table.py` manually

The script is idempotent (checks whether `iocs` already exists first, only
ever issues `CREATE TABLE`, never `DROP`/`ALTER`) and safe to run any number
of times, against sqlite (dev) or Postgres (Render). It is **not** called
from anywhere else in the codebase — no startup hook, no other script.

**Local dev:**

```bash
source venv/bin/activate && python -m web.migrate_add_ioc_table
```

**Render** (same manual-run pattern as `scripts/rotate_admin_password.py` —
see `SECURITY.md`'s password-rotation runbook — connect using the
deployment's own `DATABASE_URL`, never print anything sensitive):

- Via the Render Shell tab, if your plan has one (`DATABASE_URL` is already
  set in that environment):

  ```bash
  python -m web.migrate_add_ioc_table
  ```

- From any machine, using Render's Postgres "External Database URL" (Render
  dashboard -> your Postgres instance), exported only for this one command
  and not persisted to shell history or a committed `.env`:

  ```bash
  DATABASE_URL='postgresql+asyncpg://...' python -m web.migrate_add_ioc_table
  ```

The script prints only table/column/index/constraint *names* on success —
never row data, connection strings, or credentials. **I will not run this
against Render myself — it requires the actual Render `DATABASE_URL`, which
only you have, and applying it is a database-affecting action that needs
your explicit go-ahead per your standing instruction not to migrate
automatically.**

**Verify it worked** (either environment), via `psql` or the same pattern
used for `findings` in the 2026-07-04 diagnostic session note:

```sql
\d iocs
-- or
SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'iocs';
```

If `init_db()`'s `create_all` runs later against a database where this
script already created `iocs`, it's a no-op for that table (it already
exists) — running the script first and then booting the app normally are
not in conflict.

## What Phase 2 still needs (not part of this document's scope)

- A repository implementation backed by `web.models.Ioc` + `SessionLocal`,
  swapped into `modules.ioc.ioc_engine.IOCEngine(repository=...)` in place
  of the current in-memory `IOCRepository` stub.
- Wiring `extract_iocs_from_finding()` into the scan-save pipeline in
  `web/app.py` (same place `_finding_kwargs_from_vuln()` runs today) so
  IOCs are mined automatically as findings are persisted.
- Deciding whether `enrich_ioc()`'s `additional_sources` (OTX/IntelligenceX/
  LeakCheck) get fetched inline per-IOC or batched, given those clients are
  async and some are rate-limited (see `modules/threat_intel/otx_feed.py`
  caching, `modules/osint/unified_engine.py` timeouts).
- API routes / UI (a `/ioc` page or extending `/correlations`) — out of
  scope for this data-model phase.

None of the above touches the database and none of it is implied by simply
merging the `Ioc` model — this file exists so that when Phase 2 happens,
the actual `CREATE TABLE` step is a known, reviewed, one-way door (schema
changes are harder to undo than model/code changes), not something run
blind.
