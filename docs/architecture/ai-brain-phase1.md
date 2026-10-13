# AI Brain — Phase 1: Read-only Architecture Analysis

Branch: `feature/ai-brain`. Scope: how the existing components interact
today, where DPI/WAF decisions are made, and where authentication /
authorization lives. Nothing in this phase changes code. Every path and
symbol below was checked with `grep` against the tree at the time of writing.

## 1. Path mapping (roadmap name → actual location)

The roadmap refers to some paths that do not exist in this repository:

| Roadmap path            | Actual location in this repo                                        |
|-------------------------|---------------------------------------------------------------------|
| `main.py` / `app.py`    | `main.py` (Click CLI entry point) and `web/app.py` (FastAPI `app`)   |
| `modules/ngfw`          | `modules/firewall/ngfw_v2.py` and `modules/firewall/ai_firewall.py` |
| `modules/vpn`           | `modules/vpn/wireguard.py`                                          |
| `modules/quantum`       | `modules/quantum/encryption.py`                                     |
| `modules/ai`            | `modules/ai/` (`groq_analyzer.py`, `triage_engine.py`, ...)         |
| `modules/ai_advanced`   | `modules/ai_advanced/` (`red_team.py`, `autonomous_redteam.py`, ...) |
| `models/`               | `web/models.py` (single file, SQLAlchemy declarative)               |
| `routers/`              | `web/routers/*.py`, plus many routes defined inline in `web/app.py` |
| `auth/` / `auth/dependencies.py` | `web/auth.py` (no `auth/` package existed before this branch) |

There is also a separate "Eternal Core" subsystem under `app/` (`app/main.py`,
`app/api/v1`, `app/models/eternal`) with its own Alembic tree
(`alembic_eternal/`). It does not share the DPI or auth code discussed here.

## 2. Process entry points

- `main.py` — Click group `cli`. Command `web()` starts
  `uvicorn.run("web.app:app", ...)`; command `scan()` runs CLI scanners.
- `web/app.py` — the FastAPI instance `app`. It mounts every router via
  `app.include_router(...)` (e.g. `firewall.router`, `ngfw.router`,
  `vpn.router`, `quantum.router`, `ai_security.router`, `cve_router.router`).
- HTTP middleware in `web/app.py`: `security_headers_middleware` and
  `session_refresh_middleware`. Neither performs DPI; there is **no** global
  WAF/DPI middleware sitting in front of application traffic.
- Startup: the `@app.on_event("startup")` handler calls
  `web/database.py:init_db()`, which runs `Base.metadata.create_all` for every
  model registered on `web.database.Base`. Consequence for Phase 2: any new
  model registered on that `Base` would be created automatically at boot,
  which counts as applying a schema change. The new audit table therefore
  uses its own metadata (see §6).

## 3. Where DPI / WAF decisions are made

There are two independent rule engines. Both are invoked **on demand** by an
authenticated API call that submits a request description to inspect; neither
sits inline in front of the platform's own traffic.

### 3.1 NGFW v2 — `modules/firewall/ngfw_v2.py`

- Decision function: `async def deep_inspect(method, path, headers, body,
  src_ip, dst_port=80, protocol="HTTP", user_id=None) -> dict`.
- Inputs it combines:
  - `DPI_SIGNATURES` (regex list, each with `category`, `severity`,
    `confidence_base`);
  - `_extract_ml_features()` + `_ml_threat_score()` (heuristic, entropy-based
    via `_shannon_entropy()`);
  - `_geo_lookup()` (high-risk country flag);
  - `_check_rate_limit()` (per-IP, in-memory `_blocked_ips`);
  - User-Agent scanner regex and `SUSPICIOUS_PORTS`.
- The decision is the line
  `action = "BLOCK" if final_score >= 70 else "ALERT" if final_score >= 40 else "ALLOW"`.
- "Anomalous" in the existing engine's own terms: `deep_inspect()` increments
  `state["stats"]["anomalies"]` when `action in ("ALERT", "BLOCK")`. Phase 2
  reuses exactly this definition for sampling eligibility.
- Results are persisted to a JSON state file via `_load_state()` /
  `_save_state()` (traffic log capped at 1000).
- Callers: `web/routers/ngfw.py:inspect()` (`POST /ngfw/api/inspect`) and
  `simulate_traffic_burst()` in the same module.

### 3.2 AI Firewall (WAF) — `modules/firewall/ai_firewall.py`

- Decision function: `def inspect_request(method, path, headers, body="",
  ip="") -> dict` (synchronous).
- Signature matching over `_compiled` (pre-compiled signatures) per location
  (`url_path`, `query_params`, `request_body`, `headers`), then
  `_ml_anomaly_score()`, `_composite_risk()`.
- The decision itself is `_decide_action(threats, anomaly_score, risk_score)`,
  returning `"block" | "alert" | "allow"`.
- Callers: `web/routers/firewall.py:inspect_request_api()`
  (`POST /firewall/api/inspect`) and `analyze_log_sample()`.

### 3.3 Implication for the AI middleware

Neither engine calls an LLM. Phase 2 keeps it that way: the AI layer consumes
an already-made decision (the `action` field) and, at most, enqueues a
sampled copy for offline analysis. It never feeds back into `action`.

## 4. Existing AI modules

- `modules/ai/groq_analyzer.py` — synchronous Groq SDK client (`_client()`
  builds `groq.Groq` from `config.GROQ_API_KEY`); `analyze_findings()`,
  `natural_language_to_command()`, `summarize_recon()`. Has an LRU cache.
- `modules/ai/groq_client_utils.py` — `call_groq_sync_with_retry()` /
  `call_groq_async_with_retry()` backoff helpers.
- `modules/ai/rate_limiter.py` — `TokenBucketLimiter`, `DailyTokenBudget`,
  `get_default_daily_budget()`.
- `modules/ai/triage_engine.py` — `classify_finding()`,
  `classify_findings_batch()`.
- `modules/ai_advanced/` — `attack_patterns.analyze_text()`,
  `behavioral.BehavioralAnalyzer`, `red_team.create_engagement()`,
  `autonomous_redteam.start_autonomous_simulation()`,
  `zero_day.predict_zero_days()`.

All of these are user-initiated analysis features, not traffic-path
components.

## 5. Other modules in scope

- `modules/vpn/wireguard.py` — WireGuard config/peer management
  (`generate_server_config()`, `add_peer()`, `remove_peer()`,
  `get_wg_status()`). Router `web/routers/vpn.py` gates it with
  `require_admin(user)`.
- `modules/quantum/encryption.py` — PQC helpers (`generate_keypair()`,
  `encapsulate()`, `decapsulate()`, `sign()`, `verify()`, `encrypt_data()`),
  raising `PQCUnavailableError` when the backend is absent.

## 6. Data layer

- `web/database.py` — async engine, `SessionLocal`, `Base(DeclarativeBase)`,
  `get_db()`, `init_db()` (`create_all`).
- `web/models.py` — `User` (with `role = Column(String(20), default="viewer")
  # admin | analyst | viewer`), `DomainVerification`, `LicenseKey`,
  `PendingPayment`, and the scan/finding models.
- Migrations: there is no Alembic for the `web` app. Convention is one-off,
  idempotent, never-auto-run scripts `web/migrate_add_*_table.py` that
  generate DDL from the model's `__table__` (e.g.
  `web/migrate_add_auth_events_table.py`).

## 7. Authentication and authorization today

All in `web/auth.py`:

- `get_current_user(request, db)` — resolves the user from `X-API-Key`
  (hashed lookup via `hash_api_key()`), else `Authorization: Bearer`, else
  the `access_token` cookie; JWT validated by `decode_session_token()`.
  Raises `HTTPException(401)` on failure.
- `get_client_ip(request)` — the trusted client IP (Render/Cloudflare
  `CF-Connecting-IP`, or `X-Forwarded-For` only from `TRUSTED_PROXY_IPS`).
  ABAC must use this, never a raw header.
- `require_roles(*roles)` → `check(user)`; instances `require_admin` and
  `require_analyst_or_admin`. These are called **inline** inside handlers
  (e.g. `require_analyst_or_admin(user)` in `web/app.py:run_scan`), not via
  `Depends()`.
- The FastAPI dependency used by handlers is a thin wrapper per router:
  `web/app.py:web_user()` and `_user()` in `web/routers/ngfw.py`,
  `web/routers/firewall.py`, `web/routers/cve_submission.py`, each calling
  `get_current_user()`.
- Licensing gate: `web/license.py:require_feature_or_402(feature, user)`,
  applied alongside (not instead of) role checks.

### Endpoints relevant to the Phase 4 ABAC rules

| Roadmap resource | Endpoint(s) today                                  | Existing gate                                   |
|------------------|----------------------------------------------------|-------------------------------------------------|
| CVE Pipeline     | `web/app.py:cve_pipeline_page` (`GET /cve-pipeline`), `web/routers/cve_submission.py` (`/api/cve/*`) | authenticated + `require_feature_or_402("bug_bounty", ...)`; any role |
| SQLi scan        | `web/app.py:run_scan` (`POST /api/scan`, `scan_types` incl. `"sqli"`) | `require_analyst_or_admin(user)` + domain authorization (`web/scan_authz.py`) |
| NGFW Rules       | `web/routers/ngfw.py:get_rules` (`GET /ngfw/api/rules`) and the rest of `/ngfw/*` | authenticated + `require_feature_or_402("ngfw", ...)`; any role |

These existing gates matter for Phase 4: wiring the roadmap rules onto these
endpoints would change current behaviour (see the Phase 4 notes in the final
report).

## 8. Secrets check

A pattern scan over tracked, non-test source files (Groq/OpenAI-style keys,
AWS access keys, GitHub/Slack tokens, PEM private keys) found no hard-coded
secrets. `.env` is git-ignored and was not opened.
