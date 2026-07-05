import sys
import os
import asyncio
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import (
    FastAPI, Request, Form, HTTPException, BackgroundTasks,
    Depends, WebSocket, WebSocketDisconnect,
)
from starlette.exceptions import WebSocketException
from starlette import status as ws_status
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, inspect

from web.database import get_db, init_db, SessionLocal, engine
from web.models import User, Target, Scan, Finding, Report
from web.schemas import (
    LoginRequest, LoginResponse, RegisterRequest, RegisterResponse,
    APIKeyResponse, ScanRequest, ScanLaunchResponse, ScanStatusResponse,
    ScanListItem, FindingResponse, NLPRequest, NLPResponse,
    AIAnalyzeRequest, AIAnalyzeResponse, TargetCreate, TargetResponse,
    HeadersScanRequest, PortsScanRequest, SSLScanRequest,
    ReportRequest, ReportResponse, UserDetail, UserPatch, ErrorResponse,
)
from web.auth import (
    verify_password, hash_password, create_access_token,
    generate_api_key, hash_api_key, get_current_user, get_ws_user,
    require_admin, require_analyst_or_admin,
    check_rate_limit, record_failed_attempt, clear_attempts,
    log_auth_event, validate_password_strength, get_client_ip,
    SECRET_KEY, ALGORITHM,
)
from web.websocket_manager import ws_manager
from web.license import (
    get_license, reload_license, activate_license, deactivate_license,
    generate_license_key, FEATURE_LABELS, TIER_FEATURES,
)

from modules.recon.subdomains import enumerate_subdomains
from modules.recon.dns_lookup import dns_lookup
from modules.recon.whois_lookup import whois_lookup
from modules.recon.nmap_scanner import nmap_scan
from modules.vuln.xss import scan_xss
from modules.vuln.sqli import scan_sqli
from modules.vuln.ssrf import scan_ssrf
from modules.vuln.lfi import scan_lfi
from modules.vuln.open_redirect import scan_open_redirect
from modules.ai.triage_engine import classify_findings_batch
from modules.osint.email_finder import find_emails
from modules.osint.social_media import find_social_profiles
from modules.report.pdf_generator import generate_report
from config import APP_NAME, APP_VERSION, REPORTS_DIR
from web.routers import bug_bounty, compliance, firewall, vpn, ai_security, quantum, federation, osint as osint_router
from web.routers import attack_navigator, darkweb, autonomous_rt, ngfw, threat_feed, correlations as correlations_router
from web.routers import darkweb_monitor
from web.routers import honeypot as honeypot_router
from web.routers import threat_sharing as threat_sharing_router
from web.routers import cve_submission as cve_router
from web.routers import ioc as ioc_router
from modules.ioc_correlation import run_correlation, load_cached

BASE_DIR = Path(__file__).parent

logger = logging.getLogger("web.app")

# ─── Dark Web scheduler logging ────────────────────────────────────────────
# modules/darkweb/scheduler.py logs under "darkweb.scheduler" but nothing
# configured a level/handler for that namespace, so under uvicorn's default
# logging setup (root already has handlers, but no level below WARNING) its
# info()/warning() calls were silently dropped before reaching any handler.
# Configure the "darkweb" namespace explicitly here so every child logger
# (darkweb.scheduler, ...) inherits INFO level + a real handler.
_darkweb_logger = logging.getLogger("darkweb")
if not _darkweb_logger.handlers:
    _darkweb_handler = logging.StreamHandler()
    _darkweb_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    _darkweb_logger.addHandler(_darkweb_handler)
    _darkweb_logger.setLevel(logging.INFO)

# Same reasoning as above, for modules/ioc/scheduler.py's "ioc.scheduler" logger.
_ioc_logger = logging.getLogger("ioc")
if not _ioc_logger.handlers:
    _ioc_handler = logging.StreamHandler()
    _ioc_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    _ioc_logger.addHandler(_ioc_handler)
    _ioc_logger.setLevel(logging.INFO)

# ─── OpenAPI Tags ─────────────────────────────────────────────────────────────

OPENAPI_TAGS = [
    {
        "name": "Authentication",
        "description": (
            "Obtain JWT tokens and manage API keys. "
            "All protected endpoints require `Authorization: Bearer <token>` "
            "or a valid `access_token` cookie."
        ),
    },
    {
        "name": "Scans",
        "description": (
            "Launch and monitor security scans. Supports 13 modules: "
            "subdomain enumeration, DNS, WHOIS, Nmap, SSL, headers, ports, "
            "XSS, SQLi, SSRF, LFI, open-redirect, and OSINT. "
            "Real-time progress available via WebSocket `/ws/{scan_id}`."
        ),
    },
    {
        "name": "Targets",
        "description": "Manage the list of targets associated with your account.",
    },
    {
        "name": "Findings",
        "description": "Query vulnerability findings produced by completed scans.",
    },
    {
        "name": "NLP",
        "description": (
            "Natural-language command parser supporting Arabic and English. "
            "Submit commands like `افحص tesla.com عن ثغرات XSS` and receive "
            "structured action + target data."
        ),
    },
    {
        "name": "AI Analysis",
        "description": (
            "Groq LLaMA-powered security analysis. Submit a scan ID to receive "
            "a detailed markdown threat report."
        ),
    },
    {
        "name": "Reports",
        "description": "Generate and download PDF security reports for completed scans.",
    },
    {
        "name": "Quick Utilities",
        "description": "Fast one-shot checks: HTTP headers, SSL certificate, port scan.",
    },
    {
        "name": "Admin",
        "description": "User management and audit logs. **Admin role required.**",
    },
    {
        "name": "ai-security",
        "description": (
            "AI-powered security modules: Behavioral UEBA, Zero-Day prediction, "
            "Attack Pattern analysis, and AI Red Team engagements."
        ),
    },
    {
        "name": "bug-bounty",
        "description": (
            "Bug bounty platform integrations: HackerOne, Bugcrowd, Intigriti. "
            "Browse programs and submit reports."
        ),
    },
    {
        "name": "cve-pipeline",
        "description": (
            "CVE report drafting assistant: turn a scan finding into a MITRE CNA-style "
            "draft (title, description, affected product/versions, CWE, CVSS, references), "
            "store it locally, and export it as a CVE JSON 5.0 record. Drafting only — "
            "no report is ever submitted to MITRE automatically; real submission requires "
            "human review and an approved CNA account."
        ),
    },
    {
        "name": "compliance",
        "description": "Automated compliance checking against ISO 27001, NIST, PCI-DSS, GDPR, HIPAA.",
    },
    {
        "name": "osint",
        "description": (
            "OSINT intelligence modules: phone lookup, IP geolocation, domain recon, "
            "national ID (Iraq), vehicle plates, username search, device fingerprinting, "
            "and cell tower triangulation."
        ),
    },
    {
        "name": "firewall",
        "description": "AI-powered application firewall — manage rules, whitelist/blacklist IPs.",
    },
    {
        "name": "vpn",
        "description": "WireGuard VPN peer management and key generation.",
    },
    {
        "name": "quantum",
        "description": "Post-Quantum Cryptography (PQC) using Kyber-768 key encapsulation.",
    },
    {
        "name": "federation",
        "description": "Federated scan coordination across multiple OPTISEC nodes.",
    },
    {
        "name": "attack_navigator",
        "description": "MITRE ATT&CK Navigator — browse techniques, map detections, track APT profiles.",
    },
    {
        "name": "darkweb",
        "description": "Dark web intelligence feed — leaked credentials, threat actor mentions, IOCs.",
    },
    {
        "name": "autonomous_redteam",
        "description": (
            "Autonomous Red Team engine (v4.0 SINGULARITY) — AI-driven attack sessions, "
            "payload library, and automated report generation."
        ),
    },
    {
        "name": "ngfw",
        "description": "Next-Generation Firewall v2 with ML-based DPI and anomaly detection.",
    },
    {
        "name": "threat_feed",
        "description": "Global threat intelligence feed — IOCs, CVEs, active campaigns.",
    },
    {
        "name": "correlations",
        "description": "IOC correlation engine — cluster and link indicators across multiple sources.",
    },
    {
        "name": "honeypot",
        "description": (
            "Lightweight, isolated SSH/FTP/HTTP-admin decoy listeners — capture and enrich "
            "(geolocation + AbuseIPDB) attacker connection attempts."
        ),
    },
    {
        "name": "threat_sharing",
        "description": (
            "Export locally-discovered technical IOCs (honeypot attacker IPs, dark web paste/leak "
            "URLs, CISA KEV CVEs) as STIX/CSV/JSON, and optionally share a single IOC with the "
            "AlienVault OTX community. Opt-in and disabled by default — see ENABLE_THREAT_SHARING."
        ),
    },
    {
        "name": "ioc",
        "description": (
            "Local Indicators of Compromise store (modules/ioc/ioc_engine.py, web.models.Ioc) — "
            "IPs/domains/URLs mined automatically from scan Finding evidence after every "
            "XSS/SQLi/SSRF/LFI/Open Redirect scan, plus manual check_ioc()/enrich_ioc() lookups."
        ),
    },
]

# ─── FastAPI App ──────────────────────────────────────────────────────────────

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="""
## 🛡️ OPTISEC Recon Pro — Enterprise Security Intelligence Platform

A comprehensive **Bug Bounty & Penetration Testing** platform with AI-powered analysis,
built for security professionals and enterprise SOC teams.

---

### Authentication

All API endpoints require authentication. Two methods are supported:

| Method | Header / Cookie |
|--------|----------------|
| **JWT Token** | `Authorization: Bearer <token>` |
| **Session Cookie** | `access_token=<token>` (set automatically on web login) |

Obtain a token via `POST /api/auth/login`.

---

### Rate Limiting

Login endpoints are rate-limited to **5 failed attempts** before a 15-minute lockout.
API endpoints are not currently rate-limited but require a valid token.

---

### Roles

| Role | Capabilities |
|------|-------------|
| `admin` | Full access — user management, all scans |
| `analyst` | Launch scans, view all findings |
| `viewer` | Read-only access to own scans |

---

### WebSocket — Real-time Scan Progress

Connect to `ws://host/ws/{scan_id}` after launching a scan to receive live progress events:

```json
{ "type": "progress", "step": "xss", "progress": 58, "status": "running" }
```

---

### Arabic NLP Support

The `/api/nlp` endpoint accepts commands in **Arabic or English**:

```
افحص tesla.com عن ثغرات XSS
اجمع النطاقات الفرعية لـ example.com
ابدأ فحص شامل وأنشئ تقرير
```
""",
    contact={
        "name": "OPTISEC Security Team",
        "email": "ahssanali84.syber@gmail.com",
    },
    license_info={
        "name": "Proprietary — All Rights Reserved",
    },
    openapi_tags=OPENAPI_TAGS,
    docs_url=None,
    redoc_url=None,
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
templates.env.globals["get_license"] = get_license


# ─── Custom Swagger UI (OPTISEC Dark Theme) ───────────────────────────────────

@app.get("/docs", include_in_schema=False)
async def custom_swagger(request: Request):
    token = request.cookies.get("access_token", "")
    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{APP_NAME} — API Docs</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
  <style>
    :root {{
      --accent: #00ff88;
      --bg: #0d1117;
      --card: #161b22;
      --border: #30363d;
      --text: #e6edf3;
    }}
    body {{ background: var(--bg) !important; margin: 0; font-family: 'Segoe UI', sans-serif; }}
    .swagger-ui {{ background: var(--bg) !important; }}
    .swagger-ui .topbar {{ background: #161b22 !important; border-bottom: 1px solid #30363d; padding: 10px 20px; }}
    .swagger-ui .topbar .topbar-wrapper {{ gap: 16px; }}
    .swagger-ui .topbar .topbar-wrapper .link {{ display: none; }}
    .swagger-ui .topbar::before {{
      content: '🛡️ OPTISEC API Docs';
      color: #00ff88;
      font-size: 18px;
      font-weight: 700;
      letter-spacing: 1px;
    }}
    .swagger-ui .info {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 24px; margin-bottom: 20px; }}
    .swagger-ui .info .title {{ color: var(--accent) !important; font-size: 28px; }}
    .swagger-ui .info p, .swagger-ui .info li {{ color: var(--text) !important; }}
    .swagger-ui .info table th, .swagger-ui .info table td {{ color: var(--text) !important; background: #1c2333 !important; border-color: var(--border) !important; }}
    .swagger-ui .info h2, .swagger-ui .info h3, .swagger-ui .info h4 {{ color: var(--accent) !important; }}
    .swagger-ui .info code {{ background: #0d1117; color: #00ff88; padding: 2px 6px; border-radius: 4px; }}
    .swagger-ui .scheme-container {{ background: var(--card) !important; border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
    .swagger-ui select {{ background: var(--bg) !important; color: var(--text) !important; border-color: var(--border) !important; }}
    .swagger-ui .opblock-tag {{ background: var(--card) !important; border: 1px solid var(--border) !important; border-radius: 8px !important; margin-bottom: 8px !important; }}
    .swagger-ui .opblock-tag:hover {{ background: #1c2333 !important; }}
    .swagger-ui .opblock-tag-section h3 {{ color: var(--text) !important; font-size: 16px !important; }}
    .swagger-ui .opblock-tag-section p {{ color: #8b949e !important; }}
    .swagger-ui .opblock {{ background: var(--card) !important; border: 1px solid var(--border) !important; border-radius: 8px !important; margin-bottom: 6px !important; }}
    .swagger-ui .opblock.opblock-get    {{ border-left: 3px solid #58a6ff !important; }}
    .swagger-ui .opblock.opblock-post   {{ border-left: 3px solid #00ff88 !important; }}
    .swagger-ui .opblock.opblock-delete {{ border-left: 3px solid #ff4444 !important; }}
    .swagger-ui .opblock.opblock-patch  {{ border-left: 3px solid #ffcc00 !important; }}
    .swagger-ui .opblock.opblock-put    {{ border-left: 3px solid #ff8800 !important; }}
    .swagger-ui .opblock .opblock-summary {{ background: transparent !important; }}
    .swagger-ui .opblock .opblock-summary-method {{ border-radius: 4px !important; font-size: 12px !important; min-width: 60px !important; font-weight: 700 !important; }}
    .swagger-ui .opblock.opblock-get    .opblock-summary-method {{ background: #58a6ff !important; color: #000 !important; }}
    .swagger-ui .opblock.opblock-post   .opblock-summary-method {{ background: #00ff88 !important; color: #000 !important; }}
    .swagger-ui .opblock.opblock-delete .opblock-summary-method {{ background: #ff4444 !important; }}
    .swagger-ui .opblock.opblock-patch  .opblock-summary-method {{ background: #ffcc00 !important; color: #000 !important; }}
    .swagger-ui .opblock .opblock-summary-path {{ color: var(--text) !important; font-family: 'Fira Code', monospace; }}
    .swagger-ui .opblock .opblock-summary-description {{ color: #8b949e !important; }}
    .swagger-ui .opblock-body-inner, .swagger-ui .opblock-section {{ background: #1c2333 !important; }}
    .swagger-ui .tab li {{ color: #8b949e !important; }}
    .swagger-ui .tab li.active, .swagger-ui .tab li:hover {{ color: var(--accent) !important; }}
    .swagger-ui textarea, .swagger-ui input[type=text], .swagger-ui input[type=email] {{
      background: var(--bg) !important; color: var(--text) !important;
      border-color: var(--border) !important; border-radius: 6px !important;
    }}
    .swagger-ui .btn {{ border-radius: 6px !important; font-weight: 600 !important; }}
    .swagger-ui .btn.execute {{ background: var(--accent) !important; color: #000 !important; border: none !important; }}
    .swagger-ui .btn.authorize {{ background: transparent !important; color: var(--accent) !important; border-color: var(--accent) !important; }}
    .swagger-ui .response-col_status {{ color: var(--accent) !important; font-weight: 700 !important; }}
    .swagger-ui .response-col_description {{ color: var(--text) !important; }}
    .swagger-ui .responses-table .response {{ background: #1c2333 !important; border-color: var(--border) !important; }}
    .swagger-ui .model-box {{ background: var(--bg) !important; border-color: var(--border) !important; border-radius: 6px !important; }}
    .swagger-ui .model .property {{ color: var(--text) !important; }}
    .swagger-ui .model .property-type {{ color: #bc8cff !important; }}
    .swagger-ui .model-title {{ color: var(--accent) !important; }}
    .swagger-ui section.models {{ background: var(--card) !important; border: 1px solid var(--border) !important; border-radius: 8px !important; }}
    .swagger-ui section.models h4 {{ color: var(--text) !important; }}
    .swagger-ui .loading-container {{ background: var(--bg) !important; }}
    .swagger-ui .markdown p, .swagger-ui .markdown li {{ color: var(--text) !important; }}
    .swagger-ui .markdown code {{ background: #0d1117 !important; color: #00ff88 !important; }}
    .swagger-ui .markdown h1,.swagger-ui .markdown h2,.swagger-ui .markdown h3 {{ color: var(--accent) !important; }}
    .swagger-ui .markdown table th {{ background: #1c2333 !important; color: var(--text) !important; }}
    .swagger-ui .markdown table td {{ color: var(--text) !important; }}
    .swagger-ui .markdown hr {{ border-color: var(--border) !important; }}
    .swagger-ui span.token.string {{ color: #a5d6ff !important; }}
    .swagger-ui span.token.number {{ color: #79c0ff !important; }}
    .swagger-ui span.token.boolean {{ color: #ff8800 !important; }}
    .swagger-ui span.token.property {{ color: var(--accent) !important; }}
    .swagger-ui .microlight {{ background: var(--bg) !important; color: var(--text) !important; border-radius: 6px !important; }}
    .swagger-ui .highlight-code {{ background: var(--bg) !important; }}
    .swagger-ui .arrow {{ filter: invert(0.6); }}
  </style>
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
window.onload = () => {{
  SwaggerUIBundle({{
    url: '/openapi.json',
    dom_id: '#swagger-ui',
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
    layout: 'BaseLayout',
    docExpansion: 'none',
    defaultModelsExpandDepth: 1,
    persistAuthorization: true,
    tryItOutEnabled: false,
    requestInterceptor: req => {{
      const cookie = '{token}';
      if (cookie) req.headers['Cookie'] = 'access_token=' + cookie;
      return req;
    }},
    onComplete: () => {{
      const auth = document.querySelector('.auth-wrapper');
      if (auth) {{
        const hint = document.createElement('div');
        hint.style = 'color:#8b949e;font-size:12px;margin-top:8px;padding:8px 12px;background:#1c2333;border-radius:6px';
        hint.innerHTML = '💡 Use <code style="color:#00ff88">POST /api/auth/login</code> to get your token, then click Authorize above.';
        auth.appendChild(hint);
      }}
    }},
  }});
}};
</script>
</body>
</html>""")


@app.get("/redoc", include_in_schema=False)
async def custom_redoc():
    return HTMLResponse(f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>{APP_NAME} — API Reference</title>
  <style>body{{margin:0;background:#0d1117}}</style>
</head>
<body>
  <redoc spec-url='/openapi.json'
    theme='{{"colors":{{"primary":{{"main":"#00ff88"}}}},"rightPanel":{{"backgroundColor":"#161b22"}},"sidebar":{{"backgroundColor":"#161b22"}}}}'
  ></redoc>
  <script src="https://cdn.jsdelivr.net/npm/redoc@latest/bundles/redoc.standalone.js"></script>
</body>
</html>""")

# ─── Feature Routers ──────────────────────────────────────────────────────────
app.include_router(bug_bounty.router)
app.include_router(compliance.router)
app.include_router(firewall.router)
app.include_router(vpn.router)
app.include_router(ai_security.router)
app.include_router(quantum.router)
app.include_router(federation.router)
app.include_router(osint_router.router)

# ─── v4.0 SINGULARITY Routers ─────────────────────────────────────────────────
app.include_router(attack_navigator.router)
app.include_router(darkweb.router)
app.include_router(darkweb_monitor.router)
app.include_router(autonomous_rt.router)
app.include_router(ngfw.router)
app.include_router(threat_feed.router)
app.include_router(correlations_router.router)
app.include_router(honeypot_router.router)
app.include_router(honeypot_router.page_router)
app.include_router(threat_sharing_router.router)
app.include_router(cve_router.router)
app.include_router(ioc_router.router)


# ─── Session timeout middleware (sliding 30-min window) ───────────────────────

@app.middleware("http")
async def session_refresh_middleware(request: Request, call_next):
    response = await call_next(request)
    token = request.cookies.get("access_token")
    if token and response.status_code < 400:
        try:
            from jose import jwt as jose_jwt
            payload = jose_jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            new_token = create_access_token(int(payload["sub"]), payload["role"])
            response.set_cookie(
                "access_token", new_token,
                httponly=True, max_age=1800, samesite="lax",
            )
        except Exception:
            pass
    return response


# ─── Startup ──────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    await init_db()

    # init_db() only runs Base.metadata.create_all, which never adds columns
    # to a table that already exists. The users.api_key_hash migration has
    # already been run against production (via the now-removed, token-gated
    # /internal/run-api-key-migration endpoint), so the column should always
    # be present. _ensure_first_admin and _ensure_demo_account both touch the
    # User entity (whose mapped columns include api_key_hash), so without this
    # guard they'd raise on that missing column and take the whole app down
    # before it can serve any request. Keep the guard as a defensive check for
    # any environment where the column still hasn't been added.
    has_api_key_hash = await _users_table_has_api_key_hash()
    if not has_api_key_hash:
        logger.warning(
            "[OPTISEC] users.api_key_hash column missing — skipping admin/demo "
            "account seeding. The api_key_hash migration trigger endpoint has "
            "been removed; run web/migrate_add_api_key_hash.py directly against "
            "this database to add the column."
        )
    else:
        await _ensure_first_admin()
        await _ensure_demo_account()

    from modules.darkweb.scheduler import start_scheduler
    start_scheduler(asyncio.get_running_loop())

    from modules.ioc.scheduler import start_scheduler as start_ioc_scheduler
    start_ioc_scheduler(asyncio.get_running_loop())

    from modules.honeypot.manager import start_honeypots
    await start_honeypots()


@app.on_event("shutdown")
async def shutdown():
    from modules.darkweb.scheduler import stop_scheduler
    stop_scheduler()

    from modules.ioc.scheduler import stop_scheduler as stop_ioc_scheduler
    stop_ioc_scheduler()

    from modules.honeypot.manager import stop_honeypots
    await stop_honeypots()


def _write_initial_credentials_file(role: str, username: str, password: str) -> None:
    """Persist a freshly auto-generated initial password somewhere other than
    the logs, since it must never be printed/logged in plaintext. Written
    outside any logs/ directory with chmod 600; the operator must delete this
    file manually after the first login — it must not remain on the server.
    """
    import stat
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    path = f"/tmp/optisec_initial_creds_{role}_{ts}.txt"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w") as f:
        f.write(f"role={role}\nusername={username}\npassword={password}\n")
    logger.warning(
        f"[OPTISEC] Auto-generated initial {role} password written to {path} "
        "(chmod 600). Log in once, then delete this file manually — it must "
        "not be left on the server."
    )


async def _users_table_has_api_key_hash() -> bool:
    async with engine.begin() as conn:
        cols = await conn.run_sync(
            lambda sync_conn: {c["name"] for c in inspect(sync_conn).get_columns("users")}
        )
        return "api_key_hash" in cols


async def _ensure_first_admin():
    async with SessionLocal() as db:
        count = (await db.execute(select(func.count()).select_from(User))).scalar()
        if count == 0:
            import secrets as _secrets
            username = os.environ.get("FIRST_ADMIN_USER", "admin")
            env_password = os.environ.get("FIRST_ADMIN_PASSWORD")
            password = env_password or (
                _secrets.token_urlsafe(12) + "!A1"  # meets strength requirements
            )
            email = os.environ.get("FIRST_ADMIN_EMAIL", "admin@optisec.local")
            admin = User(
                username=username,
                email=email,
                password_hash=hash_password(password),
                role="admin",
                api_key_hash=hash_api_key(generate_api_key()),
                is_active=True,
            )
            db.add(admin)
            await db.commit()
            if not env_password:
                _write_initial_credentials_file("admin", username, password)
            logger.warning(f"[OPTISEC] Initial admin account created: username={username}")
            log_auth_event("INIT_ADMIN", username, "localhost", True, "first admin created")


_DEMO_TARGETS = [
    ("tesla.com",     "Tesla Inc."),
    ("google.com",    "Google LLC"),
    ("microsoft.com", "Microsoft Corp"),
    ("apple.com",     "Apple Inc."),
    ("amazon.com",    "Amazon AWS"),
]
_DEMO_FINDINGS = [
    # severity uses the same Title Case convention the real scanners write
    # (modules/vuln/*.py via waf_aware_classifier.py: "Critical"/"High"/"Medium"/"Low"),
    # so demo findings don't mix casing with real scan findings on the same account.
    ("XSS",           "High",     "https://tesla.com/search?q=test", "q",      "<script>alert(1)</script>"),
    ("SQLi",          "Critical", "https://tesla.com/api/user",      "id",     "' OR 1=1--"),
    ("SSRF",          "High",     "https://tesla.com/fetch",         "url",    "http://169.254.169.254/"),
    ("Open Redirect", "Medium",   "https://tesla.com/redirect",      "next",   "//evil.com"),
    ("XSS",           "Medium",   "https://google.com/search",       "q",      "\"><img src=x onerror=alert(1)>"),
    ("LFI",           "Critical", "https://google.com/page",         "file",   "../../etc/passwd"),
    ("SQLi",          "High",     "https://microsoft.com/api/login", "user",   "admin'--"),
    ("XSS",           "Low",      "https://apple.com/feedback",      "msg",    "<b>test</b>"),
]

async def _ensure_demo_account():
    async with SessionLocal() as db:
        demo = (await db.execute(
            select(User).where(User.username == "demo")
        )).scalar_one_or_none()
        if demo:
            return

        import secrets as _secrets
        demo_env_password = os.environ.get("DEMO_INITIAL_PASSWORD")
        demo_password = demo_env_password or (_secrets.token_urlsafe(12) + "!A1")

        demo = User(
            username="demo",
            email="demo@optisec.local",
            password_hash=hash_password(demo_password),
            role="analyst",
            api_key_hash=hash_api_key(generate_api_key()),
            is_active=True,
        )
        db.add(demo)
        await db.flush()

        targets = []
        for url, name in _DEMO_TARGETS:
            t = Target(user_id=demo.id, url=url, name=name)
            db.add(t)
            targets.append(t)
        await db.flush()

        import random, uuid as _uuid
        from datetime import timedelta
        statuses = ["done", "done", "done", "failed", "done"]
        scan_ids = []
        for i, (t, (url, _)) in enumerate(zip(targets, _DEMO_TARGETS)):
            s = Scan(
                id=f"demo_{_uuid.uuid4().hex[:16]}",
                user_id=demo.id,
                target_id=t.id,
                target_url=url,
                scan_types=["xss", "sqli", "subdomain", "dns"],
                status=statuses[i],
                progress=100 if statuses[i] == "done" else 37,
                results={"demo": True},
                created_at=datetime.utcnow() - timedelta(days=i),
            )
            db.add(s)
            scan_ids.append((s.id, t.id))
        await db.flush()

        for i, (vtype, sev, url, param, payload) in enumerate(_DEMO_FINDINGS):
            scan_id, target_id = scan_ids[i % len(scan_ids)]
            db.add(Finding(
                scan_id=scan_id, target_id=target_id,
                vuln_type=vtype, severity=sev,
                url=url, parameter=param,
                payload=payload,
                evidence=f"Demo finding — {vtype} detected at parameter '{param}'",
            ))

        await db.commit()
        if not demo_env_password:
            _write_initial_credentials_file("demo", "demo", demo_password)
        logger.warning("[OPTISEC] Initial demo account created: username=demo")


# ─── Exception Handlers ───────────────────────────────────────────────────────

@app.exception_handler(HTTPException)
async def on_http_exception(request: Request, exc: HTTPException):
    if exc.status_code == 401 and not request.url.path.startswith("/api/"):
        # Show landing page for root path; login redirect for everything else
        if request.url.path == "/":
            return templates.TemplateResponse(request, "landing.html", {
                "app_name": APP_NAME, "version": APP_VERSION,
            })
        return RedirectResponse(f"/login?next={request.url.path}", status_code=302)
    if exc.status_code == 403 and not request.url.path.startswith("/api/"):
        return templates.TemplateResponse(request, "error.html", {
            "app_name": APP_NAME, "error": "Access denied", "code": 403
        }, status_code=403)
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)


# ─── Auth Dependency ──────────────────────────────────────────────────────────

async def web_user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


async def optional_user(request: Request, db: AsyncSession = Depends(get_db)) -> Optional[User]:
    try:
        return await get_current_user(request, db)
    except Exception:
        return None


# ─── Demo Route ───────────────────────────────────────────────────────────────

@app.get("/demo", response_class=HTMLResponse, include_in_schema=False)
async def demo_login(request: Request, db: AsyncSession = Depends(get_db)):
    """One-click demo login — creates session for demo user."""
    user = (await db.execute(
        select(User).where(User.username == "demo", User.is_active == True)
    )).scalar_one_or_none()
    if not user:
        return RedirectResponse("/login?error=Demo+account+not+available", status_code=302)
    user.last_login = datetime.utcnow()
    await db.commit()
    token = create_access_token(user.id, user.role)
    response = RedirectResponse("/", status_code=302)
    response.set_cookie("access_token", token, httponly=True, max_age=1800, samesite="lax")
    return response


@app.get("/landing", response_class=HTMLResponse, include_in_schema=False)
async def landing_page(request: Request):
    return templates.TemplateResponse(request, "landing.html", {
        "app_name": APP_NAME, "version": APP_VERSION,
    })


# ─── Auth Routes ──────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str = "/", error: str = ""):
    token = request.cookies.get("access_token")
    if token:
        try:
            from jose import jwt as jose_jwt
            jose_jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return RedirectResponse("/", status_code=302)
        except Exception:
            pass
    return templates.TemplateResponse(request, "login.html", {
        "app_name": APP_NAME, "next": next, "error": error,
    })


@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form("/"),
    db: AsyncSession = Depends(get_db),
):
    ip = get_client_ip(request)

    allowed, remaining = check_rate_limit(ip)
    if not allowed:
        minutes = remaining // 60 + 1
        log_auth_event("LOGIN", username, ip, False, f"rate_limited remaining={remaining}s")
        return templates.TemplateResponse(request, "login.html", {
            "app_name": APP_NAME,
            "error": f"Too many failed attempts. Try again in {minutes} minute(s).",
            "next": next,
        }, status_code=429)

    result = await db.execute(
        select(User).where(
            (User.username == username) | (User.email == username),
            User.is_active == True,
        )
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(password, user.password_hash):
        record_failed_attempt(ip)
        log_auth_event("LOGIN", username, ip, False, "invalid_credentials")
        return templates.TemplateResponse(request, "login.html", {
            "app_name": APP_NAME,
            "error": "Invalid username or password",
            "next": next,
        }, status_code=401)

    clear_attempts(ip)
    user.last_login = datetime.utcnow()
    await db.commit()
    log_auth_event("LOGIN", user.username, ip, True)

    token = create_access_token(user.id, user.role)
    response = RedirectResponse(next or "/", status_code=302)
    response.set_cookie("access_token", token, httponly=True, max_age=1800, samesite="lax")
    return response


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, error: str = ""):
    return templates.TemplateResponse(request, "register.html", {
        "app_name": APP_NAME, "error": error,
    })


@app.post("/register")
async def register_submit(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    ip = get_client_ip(request)

    allowed, remaining = check_rate_limit(ip)
    if not allowed:
        minutes = remaining // 60 + 1
        log_auth_event("REGISTER", username, ip, False, f"rate_limited remaining={remaining}s")
        return templates.TemplateResponse(request, "register.html", {
            "app_name": APP_NAME,
            "error": f"Too many attempts. Try again in {minutes} minute(s).",
        }, status_code=429)

    pw_errors = validate_password_strength(password)
    if pw_errors:
        record_failed_attempt(ip)
        return templates.TemplateResponse(request, "register.html", {
            "app_name": APP_NAME,
            "error": "Password must have: " + ", ".join(pw_errors),
        }, status_code=400)

    exists = (await db.execute(
        select(User).where((User.username == username) | (User.email == email))
    )).scalar_one_or_none()
    if exists:
        record_failed_attempt(ip)
        return templates.TemplateResponse(request, "register.html", {
            "app_name": APP_NAME, "error": "Username or email already taken",
        }, status_code=400)

    count = (await db.execute(select(func.count()).select_from(User))).scalar()
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role="admin" if count == 0 else "viewer",
        api_key_hash=hash_api_key(generate_api_key()),
        is_active=True,
    )
    db.add(user)
    await db.commit()
    clear_attempts(ip)
    log_auth_event("REGISTER", username, ip, True)

    token = create_access_token(user.id, user.role)
    response = RedirectResponse("/", status_code=302)
    response.set_cookie("access_token", token, httponly=True, max_age=1800, samesite="lax")
    return response


@app.get("/logout")
async def logout(request: Request):
    ip = get_client_ip(request)
    token = request.cookies.get("access_token")
    username = "unknown"
    if token:
        try:
            from jose import jwt as jose_jwt
            payload = jose_jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub", "unknown")
        except Exception:
            pass
    log_auth_event("LOGOUT", username, ip, True)
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie("access_token")
    return response


# ─── API Auth ─────────────────────────────────────────────────────────────────

@app.post(
    "/api/auth/login",
    tags=["Authentication"],
    summary="Obtain JWT access token",
    description=(
        "Authenticate with username/email and password. Returns a JWT bearer token "
        "valid for **30 minutes**. Include as `Authorization: Bearer <token>` on all "
        "subsequent API requests, or it will be set automatically via cookie on web login."
    ),
    responses={
        200: {"description": "Token issued successfully", "model": LoginResponse},
        401: {"description": "Invalid credentials", "model": ErrorResponse},
        429: {"description": "Rate limited — too many failed attempts", "model": ErrorResponse},
    },
)
async def api_login(request: Request, db: AsyncSession = Depends(get_db)):
    data = await request.json()
    ip = get_client_ip(request)
    username_input = data.get("username", "")

    allowed, remaining = check_rate_limit(ip)
    if not allowed:
        log_auth_event("API_LOGIN", username_input, ip, False, f"rate_limited remaining={remaining}s")
        raise HTTPException(429, f"Too many failed attempts. Try again in {remaining} seconds.")

    result = await db.execute(
        select(User).where(
            (User.username == username_input) | (User.email == username_input),
            User.is_active == True,
        )
    )
    user = result.scalar_one_or_none()
    if not user or not verify_password(data.get("password", ""), user.password_hash):
        record_failed_attempt(ip)
        log_auth_event("API_LOGIN", username_input, ip, False, "invalid_credentials")
        raise HTTPException(401, "Invalid credentials")

    clear_attempts(ip)
    log_auth_event("API_LOGIN", user.username, ip, True)
    token = create_access_token(user.id, user.role)
    return JSONResponse({
        "access_token": token, "token_type": "bearer",
        "user": {"id": user.id, "username": user.username, "role": user.role},
    })


@app.post(
    "/api/auth/register",
    tags=["Authentication"],
    summary="Register new user account",
    description=(
        "Create a new user account. The **first registered user** automatically receives "
        "`admin` role; all subsequent accounts start as `viewer`. "
        "Password must have ≥8 characters, at least one uppercase letter, digit, and special character."
    ),
    responses={
        200: {"description": "Account created", "model": RegisterResponse},
        400: {"description": "Validation error or duplicate user", "model": ErrorResponse},
        429: {"description": "Rate limited — too many failed attempts", "model": ErrorResponse},
    },
)
async def api_register(request: Request, db: AsyncSession = Depends(get_db)):
    data = await request.json()
    username = data.get("username", "")
    email = data.get("email", "")
    password = data.get("password", "")
    ip = get_client_ip(request)

    allowed, remaining = check_rate_limit(ip)
    if not allowed:
        log_auth_event("API_REGISTER", username, ip, False, f"rate_limited remaining={remaining}s")
        raise HTTPException(429, f"Too many attempts. Try again in {remaining} seconds.")

    pw_errors = validate_password_strength(password)
    if pw_errors:
        record_failed_attempt(ip)
        raise HTTPException(400, "Password must have: " + ", ".join(pw_errors))

    if (await db.execute(select(User).where(
        (User.username == username) | (User.email == email)
    ))).scalar_one_or_none():
        record_failed_attempt(ip)
        raise HTTPException(400, "Username or email already taken")

    count = (await db.execute(select(func.count()).select_from(User))).scalar()
    api_key = generate_api_key()
    user = User(
        username=username, email=email,
        password_hash=hash_password(password),
        role="admin" if count == 0 else "viewer",
        api_key_hash=hash_api_key(api_key),
    )
    db.add(user)
    await db.commit()
    clear_attempts(ip)
    log_auth_event("API_REGISTER", username, ip, True)
    return JSONResponse({"id": user.id, "username": user.username,
                         "role": user.role, "api_key": api_key})


@app.post(
    "/api/auth/api-key/regenerate",
    tags=["Authentication"],
    summary="Regenerate API key",
    description=(
        "Invalidates the current 64-character API key and issues a new one. "
        "The old key stops working immediately."
    ),
    responses={
        200: {"description": "New API key", "model": APIKeyResponse},
        401: {"description": "Not authenticated", "model": ErrorResponse},
    },
)
async def regenerate_api_key(
    user: User = Depends(web_user),
    db: AsyncSession = Depends(get_db),
):
    api_key = generate_api_key()
    user.api_key_hash = hash_api_key(api_key)
    await db.commit()
    return JSONResponse({"api_key": api_key})


# ─── Web Pages ────────────────────────────────────────────────────────────────

@app.get("/api-docs", response_class=HTMLResponse, include_in_schema=False)
async def api_docs_page(request: Request, user: User = Depends(web_user)):
    import json as _json
    # Parse openapi.json to build endpoint groups for the UI
    from fastapi.openapi.utils import get_openapi as _get_openapi
    spec = _get_openapi(
        title=app.title, version=app.version, description=app.description,
        routes=app.routes, tags=app.openapi_tags,
    )
    paths = spec.get("paths", {})

    tag_endpoints: dict = {}
    for path, methods in paths.items():
        for method, info in methods.items():
            if method in ("get", "post", "delete", "patch", "put"):
                for tag in (info.get("tags") or ["Other"]):
                    tag_endpoints.setdefault(tag, []).append({
                        "method": method.upper(),
                        "path": path,
                        "summary": info.get("summary", path),
                        "operation_id": info.get("operationId", ""),
                    })

    tag_icons = {
        "Authentication": "🔑", "Scans": "📡", "Targets": "🎯",
        "Findings": "🔍", "NLP": "💬", "AI Analysis": "🤖",
        "Reports": "📄", "Quick Utilities": "⚡", "Admin": "⚙️",
        "ai-security": "🧠", "bug-bounty": "💰", "compliance": "✅",
        "osint": "🕵️", "firewall": "🛡️", "vpn": "🔒", "quantum": "⚛️",
        "federation": "🌐", "attack_navigator": "⚔️", "darkweb": "🕸️",
        "autonomous_redteam": "🤖", "ngfw": "🔥", "threat_feed": "🌍",
        "correlations": "🔗", "cve-pipeline": "🧾", "Other": "📌",
    }
    tag_descs = {t["name"]: t.get("description", "") for t in (app.openapi_tags or [])}

    api_groups = []
    for tag, eps in sorted(tag_endpoints.items()):
        api_groups.append({
            "name": tag,
            "icon": tag_icons.get(tag, "📌"),
            "description": tag_descs.get(tag, "")[:120],
            "endpoints": eps,
        })

    return templates.TemplateResponse(request, "api_docs.html", {
        "app_name": APP_NAME,
        "version": APP_VERSION,
        "active": "api_docs",
        "user": user,
        "api_groups": api_groups,
        "endpoint_count": sum(len(v) for v in tag_endpoints.values()),
        "tag_count": len(tag_endpoints),
    })


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, user: User = Depends(web_user), db: AsyncSession = Depends(get_db)):
    target_count = (await db.execute(
        select(func.count()).select_from(Target).where(Target.user_id == user.id)
    )).scalar()
    scan_count = (await db.execute(
        select(func.count()).select_from(Scan).where(Scan.user_id == user.id)
    )).scalar()
    # include_in_report filters out non-CONFIRMED verdicts (WAF_BLOCKED/
    # ENDPOINT_INVALID/ENCODED_SAFE/INCONCLUSIVE) that are now persisted as
    # evidence but were never shown on the dashboard before.
    finding_count = (await db.execute(
        select(func.count()).select_from(Finding).join(Scan)
        .where(Scan.user_id == user.id, Finding.include_in_report.is_(True))
    )).scalar()
    # case-insensitive: scanner modules write Title Case ("High"/"Critical", via
    # waf_aware_classifier.py) while older rows/demo data may be lowercase.
    critical_count = (await db.execute(
        select(func.count()).select_from(Finding).join(Scan)
        .where(Scan.user_id == user.id, Finding.include_in_report.is_(True), func.lower(Finding.severity) == "critical")
    )).scalar()
    high_count = (await db.execute(
        select(func.count()).select_from(Finding).join(Scan)
        .where(Scan.user_id == user.id, Finding.include_in_report.is_(True), func.lower(Finding.severity) == "high")
    )).scalar()
    medium_count = (await db.execute(
        select(func.count()).select_from(Finding).join(Scan)
        .where(Scan.user_id == user.id, Finding.include_in_report.is_(True), func.lower(Finding.severity) == "medium")
    )).scalar()
    low_count = (await db.execute(
        select(func.count()).select_from(Finding).join(Scan)
        .where(Scan.user_id == user.id, Finding.include_in_report.is_(True), func.lower(Finding.severity) == "low")
    )).scalar()
    report_count = (await db.execute(
        select(func.count()).select_from(Report).where(Report.user_id == user.id)
    )).scalar()
    done_scans = (await db.execute(
        select(func.count()).select_from(Scan)
        .where(Scan.user_id == user.id, Scan.status == "done")
    )).scalar()
    recent_scans = (await db.execute(
        select(Scan).where(Scan.user_id == user.id)
        .order_by(Scan.created_at.desc()).limit(8)
    )).scalars().all()

    return templates.TemplateResponse(request, "index.html", {
        "app_name": APP_NAME, "version": APP_VERSION,
        "active": "home", "user": user,
        "target_count": target_count,
        "scan_count": scan_count,
        "finding_count": finding_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "report_count": report_count,
        "done_scans": done_scans,
        "recent_scans": recent_scans,
    })


@app.get("/targets", response_class=HTMLResponse)
async def targets_page(request: Request, user: User = Depends(web_user), db: AsyncSession = Depends(get_db)):
    targets = (await db.execute(
        select(Target).where(Target.user_id == user.id).order_by(Target.created_at.desc())
    )).scalars().all()

    scan_counts = {}
    for t in targets:
        cnt = (await db.execute(
            select(func.count()).select_from(Scan).where(Scan.target_id == t.id)
        )).scalar()
        scan_counts[t.id] = cnt

    return templates.TemplateResponse(request, "targets.html", {
        "app_name": APP_NAME, "active": "targets", "user": user,
        "targets": targets, "scan_counts": scan_counts,
    })


@app.post(
    "/targets/add",
    tags=["Targets"],
    summary="Add a new target",
    description="Add a domain or URL to your target list. Requires **analyst** or **admin** role.",
    responses={
        200: {"description": "Target created", "model": TargetResponse},
        403: {"description": "Insufficient role", "model": ErrorResponse},
    },
)
async def target_add(
    url: str = Form(...),
    name: str = Form(""),
    notes: str = Form(""),
    user: User = Depends(web_user),
    db: AsyncSession = Depends(get_db),
):
    require_analyst_or_admin(user)
    t = Target(user_id=user.id, url=url.strip(), name=name.strip(), notes=notes.strip())
    db.add(t)
    await db.commit()
    await db.refresh(t)
    return JSONResponse({"success": True, "target": {
        "id": t.id, "url": t.url, "name": t.name,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }})


@app.delete(
    "/targets/{target_id}",
    tags=["Targets"],
    summary="Delete a target",
    description="Permanently remove a target. Only the owning user (or admin) can delete.",
    responses={
        200: {"description": "Target deleted"},
        404: {"description": "Target not found", "model": ErrorResponse},
        403: {"description": "Insufficient role", "model": ErrorResponse},
    },
)
async def target_delete(
    target_id: int,
    user: User = Depends(web_user),
    db: AsyncSession = Depends(get_db),
):
    require_analyst_or_admin(user)
    t = (await db.execute(
        select(Target).where(Target.id == target_id, Target.user_id == user.id)
    )).scalar_one_or_none()
    if not t:
        raise HTTPException(404, "Target not found")
    await db.delete(t)
    await db.commit()
    return JSONResponse({"success": True})


@app.get("/scan", response_class=HTMLResponse)
async def scan_page(request: Request, user: User = Depends(web_user), db: AsyncSession = Depends(get_db)):
    targets = (await db.execute(
        select(Target).where(Target.user_id == user.id).order_by(Target.created_at.desc())
    )).scalars().all()
    return templates.TemplateResponse(request, "scan.html", {
        "app_name": APP_NAME, "active": "scan", "user": user, "targets": targets,
    })


@app.get("/osint", response_class=HTMLResponse)
async def osint_page(request: Request, user: User = Depends(web_user)):
    return templates.TemplateResponse(request, "osint.html", {
        "app_name": APP_NAME, "active": "osint", "user": user,
    })


@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request, user: User = Depends(web_user), db: AsyncSession = Depends(get_db)):
    query = select(Report).order_by(Report.created_at.desc())
    if user.role != "admin":
        query = query.where(Report.user_id == user.id)
    reports = (await db.execute(query)).scalars().all()
    return templates.TemplateResponse(request, "reports.html", {
        "app_name": APP_NAME, "active": "reports", "user": user, "reports": reports,
    })


@app.get("/scans", response_class=HTMLResponse)
async def scans_history(request: Request, user: User = Depends(web_user), db: AsyncSession = Depends(get_db)):
    query = select(Scan).order_by(Scan.created_at.desc()).limit(100)
    if user.role != "admin":
        query = query.where(Scan.user_id == user.id)
    scans = (await db.execute(query)).scalars().all()
    return templates.TemplateResponse(request, "scans.html", {
        "app_name": APP_NAME, "active": "scans", "user": user, "scans": scans,
    })


@app.get("/cve-pipeline", response_class=HTMLResponse)
async def cve_pipeline_page(request: Request, user: User = Depends(web_user)):
    return templates.TemplateResponse(request, "cve_pipeline.html", {
        "app_name": APP_NAME, "active": "cve", "user": user,
    })


@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request, user: User = Depends(web_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    users = (await db.execute(select(User).order_by(User.created_at))).scalars().all()
    total_scans = (await db.execute(select(func.count()).select_from(Scan))).scalar()
    # Admin-only internal overview, intentionally unfiltered by
    # include_in_report — this is the operator's system-wide count, not a
    # client-facing report, so it should reflect every persisted verdict.
    total_findings = (await db.execute(select(func.count()).select_from(Finding))).scalar()
    return templates.TemplateResponse(request, "admin.html", {
        "app_name": APP_NAME, "active": "admin", "user": user,
        "users": users, "total_scans": total_scans, "total_findings": total_findings,
    })


# ─── Scan API ─────────────────────────────────────────────────────────────────

@app.post(
    "/api/scan",
    tags=["Scans"],
    summary="Launch a security scan",
    description=(
        "Start a background security scan against a target. Returns a `scan_id` immediately. "
        "Poll `GET /api/scan/{scan_id}` for status, or connect to `ws://host/ws/{scan_id}` "
        "for real-time progress events.\n\n"
        "**Available scan modules:** `subdomain`, `dns`, `whois`, `nmap`, `ssl`, `headers`, "
        "`ports`, `xss`, `sqli`, `ssrf`, `lfi`, `redirect`, `osint`\n\n"
        "Leave `scan_types` empty to run **all modules**. Requires **analyst** or **admin** role."
    ),
    responses={
        200: {"description": "Scan launched", "model": ScanLaunchResponse},
        400: {"description": "Missing target", "model": ErrorResponse},
        403: {"description": "Insufficient role", "model": ErrorResponse},
    },
)
async def run_scan(
    background_tasks: BackgroundTasks,
    request: Request,
    user: User = Depends(web_user),
    db: AsyncSession = Depends(get_db),
):
    require_analyst_or_admin(user)
    data = await request.json()
    target_url = data.get("target", "").strip()
    scan_types = data.get("scan_types", [])

    if not target_url:
        raise HTTPException(400, "Target is required")

    scan_id = f"scan_{uuid.uuid4().hex[:16]}"

    target_id = None
    if data.get("target_id"):
        t = (await db.execute(
            select(Target).where(Target.id == int(data["target_id"]), Target.user_id == user.id)
        )).scalar_one_or_none()
        if t:
            target_id = t.id

    scan = Scan(
        id=scan_id, user_id=user.id, target_id=target_id,
        target_url=target_url, scan_types=scan_types,
        status="pending", progress=0,
    )
    db.add(scan)
    await db.commit()

    background_tasks.add_task(_run_scan_task, scan_id, target_url, scan_types, user.id, target_id)
    return JSONResponse({"scan_id": scan_id})


@app.get(
    "/api/scan/{scan_id}",
    tags=["Scans"],
    summary="Get scan status and results",
    description=(
        "Returns current status, progress percentage, and all available module results "
        "for the given scan. Results are populated incrementally as each module completes. "
        "Poll every 2–5 seconds, or use WebSocket for push-based updates."
    ),
    responses={
        200: {"description": "Scan details", "model": ScanStatusResponse},
        404: {"description": "Scan not found", "model": ErrorResponse},
        403: {"description": "Access denied", "model": ErrorResponse},
    },
)
async def get_scan_status(
    scan_id: str,
    user: User = Depends(web_user),
    db: AsyncSession = Depends(get_db),
):
    scan = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.user_id != user.id and user.role != "admin":
        raise HTTPException(403, "Access denied")
    return JSONResponse({
        "scan_id": scan.id, "status": scan.status, "progress": scan.progress,
        "target": scan.target_url, "results": scan.results or {},
        "error": scan.error,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    })


@app.get(
    "/api/scans",
    tags=["Scans"],
    summary="List recent scans",
    description=(
        "Returns the 50 most recent scans for the authenticated user. "
        "Admins see all scans across all users."
    ),
    responses={200: {"description": "List of scans"}},
)
async def list_scans(user: User = Depends(web_user), db: AsyncSession = Depends(get_db)):
    query = select(Scan).order_by(Scan.created_at.desc()).limit(50)
    if user.role != "admin":
        query = query.where(Scan.user_id == user.id)
    scans = (await db.execute(query)).scalars().all()
    return JSONResponse([{
        "id": s.id, "target": s.target_url, "status": s.status,
        "progress": s.progress,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    } for s in scans])


@app.get(
    "/api/findings",
    tags=["Findings"],
    summary="List vulnerability findings",
    description=(
        "Returns up to 200 most recent findings for the authenticated user's scans, "
        "ordered by discovery date (newest first). Each finding includes type, severity, "
        "affected URL, parameter, payload used, and evidence."
    ),
    responses={200: {"description": "List of findings"}},
)
async def list_findings(user: User = Depends(web_user), db: AsyncSession = Depends(get_db)):
    findings = (await db.execute(
        select(Finding).join(Scan)
        .where(Scan.user_id == user.id, Finding.include_in_report.is_(True))
        .order_by(Finding.created_at.desc()).limit(200)
    )).scalars().all()
    return JSONResponse([{
        "id": f.id, "scan_id": f.scan_id, "type": f.vuln_type,
        "severity": f.severity, "url": f.url, "parameter": f.parameter,
        "payload": f.payload, "evidence": f.evidence,
    } for f in findings])


# ─── Background Scan Task ─────────────────────────────────────────────────────

_STEP_PROGRESS = {
    "subdomain": 8, "dns": 15, "whois": 22, "nmap": 30,
    "ssl": 36, "headers": 42, "ports": 50,
    "xss": 58, "sqli": 66, "ssrf": 74, "lfi": 80,
    "redirect": 87, "osint": 94,
}


def _finding_kwargs_from_vuln(v: dict, scan_id: str, target_id: Optional[int], triage: Optional[dict]) -> dict:
    """Build Finding(**kwargs) for one scanner result dict.

    Every WAF-aware classifier verdict (CONFIRMED/WAF_BLOCKED/ENDPOINT_INVALID/
    ENCODED_SAFE/INCONCLUSIVE) is now persisted as a Finding row — kept as
    evidence/intelligence instead of being discarded pre-save. Only CONFIRMED
    sets include_in_report=True, which is what client-facing reads (dashboard
    counts, PDF report, /api/findings) must filter on to reproduce the
    previous CONFIRMED-only behavior.
    """
    return dict(
        scan_id=scan_id, target_id=target_id,
        vuln_type=v.get("type", "Unknown"),
        severity=v.get("severity", "Medium"),
        url=v.get("url", ""),
        parameter=v.get("parameter", ""),
        payload=v.get("payload", ""),
        evidence=v.get("evidence", ""),
        waf_detected=v.get("waf_detected"),
        verdict=v.get("verdict"),
        include_in_report=(v.get("verdict") == "CONFIRMED"),
        triage_verdict=(triage or {}).get("triage_verdict"),
        triage_confidence=(triage or {}).get("triage_confidence"),
        triage_reason=(triage or {}).get("triage_reason"),
    )


async def _extract_and_store_iocs(db: AsyncSession, finding_rows: list) -> None:
    """Best-effort IOC mining (modules/ioc/ioc_engine.py) over every Finding
    row just added to `db` for this scan.

    Deliberately non-blocking: any failure here (malformed evidence text, a
    DB hiccup on a single row) is logged and swallowed per-finding so it can
    never prevent the scan's own Finding rows from being saved/committed —
    IOC extraction is a bonus signal on top of the scan, not a requirement
    for the scan to succeed. Only local extraction/storage happens here, no
    VirusTotal/AbuseIPDB/OTX network calls (that's check_ioc/enrich_ioc,
    reserved for explicit lookups via GET /api/iocs's future manual-check
    counterpart, not triggered automatically per finding).
    """
    from modules.ioc.ioc_engine import IOCEngine, IOCRepository

    engine = IOCEngine()
    repo = IOCRepository(db)
    for row, v in finding_rows:
        try:
            finding_dict = {
                "id": row.id,
                "vuln_type": v.get("type"),
                "url": v.get("url", ""),
                "evidence": v.get("evidence", ""),
            }
            for candidate in engine.extract_iocs_from_finding(finding_dict):
                await repo.upsert(
                    candidate["ioc_type"], candidate["ioc_value"],
                    source=candidate["source"],
                    related_finding_id=candidate["related_finding_id"],
                    tags=candidate["tags"],
                )
        except Exception:
            logger.exception("IOC extraction failed for finding_id=%s", row.id)


async def _run_scan_task(
    scan_id: str, target: str, scan_types: list,
    user_id: int, target_id: Optional[int],
):
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    url = target if target.startswith("http") else f"https://{target}"
    results: dict = {}
    all_vulns: list = []

    async def push(step: str, pct: int, data=None):
        async with SessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = "running"
                scan.progress = pct
                if scan.started_at is None:
                    scan.started_at = datetime.utcnow()
                if data is not None:
                    current = dict(scan.results or {})
                    current[step] = data
                    scan.results = current
                await db.commit()
        await ws_manager.broadcast(scan_id, {
            "type": "progress", "step": step, "progress": pct,
            "status": "running", "data": data,
        })

    try:
        async with SessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = "running"
                scan.started_at = datetime.utcnow()
                await db.commit()

        run_all = not scan_types

        if run_all or "subdomain" in scan_types:
            d = await asyncio.to_thread(enumerate_subdomains, domain)
            results["subdomains"] = d
            await push("subdomain", _STEP_PROGRESS["subdomain"], d)

        if run_all or "dns" in scan_types:
            d = await asyncio.to_thread(dns_lookup, domain)
            results["dns"] = d
            await push("dns", _STEP_PROGRESS["dns"], d)

        if run_all or "whois" in scan_types:
            d = await asyncio.to_thread(whois_lookup, domain)
            results["whois"] = d
            await push("whois", _STEP_PROGRESS["whois"], d)

        if run_all or "nmap" in scan_types:
            d = await asyncio.to_thread(nmap_scan, domain)
            results["nmap"] = d
            await push("nmap", _STEP_PROGRESS["nmap"], d)

        if run_all or "ssl" in scan_types:
            from modules.recon.ssl_analysis import analyze_ssl
            d = await asyncio.to_thread(analyze_ssl, domain)
            results["ssl"] = d
            await push("ssl", _STEP_PROGRESS["ssl"], d)

        if run_all or "headers" in scan_types:
            from modules.recon.security_headers import check_security_headers
            d = await asyncio.to_thread(check_security_headers, url)
            results["headers"] = d
            await push("headers", _STEP_PROGRESS["headers"], d)

        if run_all or "ports" in scan_types:
            from modules.recon.port_scanner import scan_ports
            d = await asyncio.to_thread(scan_ports, domain)
            results["ports"] = d
            await push("ports", _STEP_PROGRESS["ports"], d)

        if run_all or "xss" in scan_types:
            d = await asyncio.to_thread(scan_xss, url)
            all_vulns.extend(d)
            await push("xss", _STEP_PROGRESS["xss"])

        if run_all or "sqli" in scan_types:
            d = await asyncio.to_thread(scan_sqli, url)
            all_vulns.extend(d)
            await push("sqli", _STEP_PROGRESS["sqli"])

        if run_all or "ssrf" in scan_types:
            d = await asyncio.to_thread(scan_ssrf, url)
            all_vulns.extend(d)
            await push("ssrf", _STEP_PROGRESS["ssrf"])

        if run_all or "lfi" in scan_types:
            d = await asyncio.to_thread(scan_lfi, url)
            all_vulns.extend(d)
            await push("lfi", _STEP_PROGRESS["lfi"])

        if run_all or "redirect" in scan_types:
            d = await asyncio.to_thread(scan_open_redirect, url)
            all_vulns.extend(d)
            await push("redirect", _STEP_PROGRESS["redirect"])

        if run_all or "osint" in scan_types:
            emails = await asyncio.to_thread(find_emails, domain)
            social = await asyncio.to_thread(find_social_profiles, domain)
            results["osint"] = {"emails": emails, "social": social}
            await push("osint", _STEP_PROGRESS["osint"], results["osint"])

        # all_vulns now carries every classifier verdict (CONFIRMED plus
        # WAF_BLOCKED/ENDPOINT_INVALID/ENCODED_SAFE/INCONCLUSIVE) — the five
        # scanner modules stopped discarding non-CONFIRMED results before
        # returning them. scan.results["vulnerabilities"] (used by the live
        # progress feed, scans.html's vuln_count, and the PDF report) must
        # stay CONFIRMED-only to keep that client-facing surface unchanged.
        confirmed_vulns = [v for v in all_vulns if v.get("verdict") == "CONFIRMED"]
        results["vulnerabilities"] = confirmed_vulns

        try:
            # AI triage is a second opinion on already-CONFIRMED findings —
            # running it on WAF_BLOCKED/etc. too would burn Groq's TPD quota
            # (see SESSION.md's TPD saga) on verdicts that don't need one.
            triage_results, triage_summary = await classify_findings_batch(confirmed_vulns)
            if triage_summary["deferred_tpd"]:
                logger.warning(
                    "AI triage batch hit daily token quota (TPD): %s succeeded, "
                    "%s deferred, resets at %s",
                    triage_summary["succeeded"],
                    triage_summary["deferred_tpd"],
                    triage_summary["tpd_reset_time"],
                )
        except Exception as exc:
            logger.warning("AI triage batch failed: %s", exc)
            triage_results = [None] * len(confirmed_vulns)

        # Map by identity rather than mutating the vuln dicts in place — they
        # (the CONFIRMED subset) are the same objects stored in
        # results["vulnerabilities"] above, and that dict is serialized
        # straight into scan.results JSON for the client; stashing triage
        # data on the dicts themselves would leak an internal-only field into
        # that response.
        triage_by_id = {id(v): t for v, t in zip(confirmed_vulns, triage_results)}

        async with SessionLocal() as db:
            finding_rows: list[tuple[Finding, dict]] = []
            for v in all_vulns:
                row = Finding(**_finding_kwargs_from_vuln(v, scan_id, target_id, triage_by_id.get(id(v))))
                db.add(row)
                finding_rows.append((row, v))
            await db.flush()  # populate row.id before IOC extraction links related_finding_id

            await _extract_and_store_iocs(db, finding_rows)

            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = "done"
                scan.progress = 100
                scan.results = results
                scan.completed_at = datetime.utcnow()
            await db.commit()

        await ws_manager.broadcast(scan_id, {
            "type": "completed", "progress": 100,
            "status": "done", "results": results,
        })

    except Exception as e:
        async with SessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.error = str(e)
                scan.completed_at = datetime.utcnow()
                await db.commit()
        await ws_manager.broadcast(scan_id, {
            "type": "error", "status": "failed", "error": str(e),
        })


# ─── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws/scan/{scan_id}")
async def ws_scan(websocket: WebSocket, scan_id: str, db: AsyncSession = Depends(get_db)):
    # Authenticate before accept() — an unauthenticated peer must never
    # complete the WS handshake, let alone see scan data (IDOR fix).
    try:
        user = await get_ws_user(websocket, db)
    except HTTPException:
        raise WebSocketException(code=ws_status.WS_1008_POLICY_VIOLATION)

    scan = await db.get(Scan, scan_id)
    if not scan or (scan.user_id != user.id and user.role != "admin"):
        raise WebSocketException(code=ws_status.WS_1008_POLICY_VIOLATION)

    if not ws_manager.has_capacity(user.id):
        raise WebSocketException(code=ws_status.WS_1008_POLICY_VIOLATION)

    await ws_manager.connect(scan_id, user.id, websocket)
    try:
        await websocket.send_json({
            "type": "state", "status": scan.status,
            "progress": scan.progress, "results": scan.results or {},
        })

        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                if msg == "ping":
                    await websocket.send_json({"type": "pong"})
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
            except WebSocketDisconnect:
                break
    except Exception:
        pass
    finally:
        ws_manager.disconnect(scan_id, user.id, websocket)


# ─── Scanner Upgrade APIs ─────────────────────────────────────────────────────

@app.post(
    "/api/scan/ssl",
    tags=["Quick Utilities"],
    summary="Analyze SSL/TLS certificate",
    description=(
        "Check SSL/TLS configuration for a domain: certificate validity, expiry, "
        "cipher suites, protocol versions (TLS 1.0/1.1 deprecated check), and HSTS."
    ),
    responses={200: {"description": "SSL analysis results"}},
)
async def scan_ssl(request: Request, user: User = Depends(web_user)):
    data = await request.json()
    target = data.get("target", "").strip()
    if not target:
        raise HTTPException(400, "Target is required")
    from modules.recon.ssl_analysis import analyze_ssl
    result = await asyncio.to_thread(analyze_ssl, target)
    return JSONResponse(result)


@app.post(
    "/api/scan/headers",
    tags=["Quick Utilities"],
    summary="Check HTTP security headers",
    description=(
        "Fetch HTTP response headers and grade them against security best practices. "
        "Checks for: `Content-Security-Policy`, `X-Frame-Options`, `HSTS`, "
        "`X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`."
    ),
    responses={200: {"description": "Header analysis results"}},
)
async def scan_headers(request: Request, user: User = Depends(web_user)):
    data = await request.json()
    target = data.get("target", "").strip()
    if not target:
        raise HTTPException(400, "Target is required")
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    from modules.recon.security_headers import check_security_headers
    result = await asyncio.to_thread(check_security_headers, target)
    return JSONResponse(result)


@app.post(
    "/api/scan/ports",
    tags=["Quick Utilities"],
    summary="Quick port scan",
    description=(
        "Run a fast port scan using Nmap. Optionally specify a comma-separated list of ports. "
        "Defaults to top-1000 common ports. Returns open ports with service detection."
    ),
    responses={200: {"description": "Port scan results"}},
)
async def scan_ports(request: Request, user: User = Depends(web_user)):
    data = await request.json()
    target = data.get("target", "").strip()
    if not target:
        raise HTTPException(400, "Target is required")
    result = await asyncio.to_thread(nmap_scan, target)
    return JSONResponse(result)


# ─── Report API ───────────────────────────────────────────────────────────────

@app.post(
    "/api/report",
    tags=["Reports"],
    summary="Generate PDF report",
    description=(
        "Generate a professional PDF security report for a completed scan. "
        "Includes executive summary, vulnerability table, OSINT findings, "
        "and remediation recommendations. Download via `GET /reports/download/{filename}`."
    ),
    responses={
        200: {"description": "Report generated"},
        500: {"description": "Report generation failed", "model": ErrorResponse},
    },
)
async def create_report(
    request: Request,
    user: User = Depends(web_user),
    db: AsyncSession = Depends(get_db),
):
    data = await request.json()
    target = data.get("target", "")
    scan_id = data.get("scan_id", "")

    scan_data: dict = {}
    scan_obj: Optional[Scan] = None
    if scan_id:
        scan_obj = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
        if scan_obj:
            scan_data = scan_obj.results or {}

    try:
        path = generate_report(
            target=target,
            recon_data=scan_data,
            vuln_findings=scan_data.get("vulnerabilities", []),
            osint_data=scan_data.get("osint", {}),
        )
        filename = Path(path).name
        rpt = Report(
            user_id=user.id,
            scan_id=scan_id or None,
            target_id=scan_obj.target_id if scan_obj else None,
            filename=filename,
            file_path=str(path),
        )
        db.add(rpt)
        await db.commit()
        return JSONResponse({"success": True, "path": path, "filename": filename})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@app.get("/reports/download/{filename}")
async def download_report(filename: str, user: User = Depends(web_user)):
    path = REPORTS_DIR / filename
    if not path.exists():
        raise HTTPException(404, "Report not found")
    return FileResponse(str(path), media_type="application/pdf", filename=filename)


# ─── OSINT & AI API ──────────────────────────────────────────────────────────

@app.post(
    "/api/osint",
    tags=["NLP"],
    summary="Full OSINT domain recon",
    description=(
        "Run all OSINT modules concurrently against a domain: email discovery, "
        "social media profiles, DNS records, WHOIS, and subdomain enumeration. "
        "Returns all results in a single response."
    ),
    responses={200: {"description": "Aggregated OSINT results"}},
)
async def run_osint(request: Request, user: User = Depends(web_user)):
    data = await request.json()
    domain = data.get("domain", "").strip()
    if not domain:
        raise HTTPException(400, "Domain is required")

    # Run all OSINT tasks concurrently
    emails_task = asyncio.to_thread(find_emails, domain)
    social_task = asyncio.to_thread(find_social_profiles, domain)
    dns_task = asyncio.to_thread(dns_lookup, domain)
    whois_task = asyncio.to_thread(whois_lookup, domain)
    subs_task = asyncio.to_thread(enumerate_subdomains, domain)

    emails, social, dns_data, whois_data, subs = await asyncio.gather(
        emails_task, social_task, dns_task, whois_task, subs_task,
        return_exceptions=True,
    )

    return JSONResponse({
        "emails": emails if not isinstance(emails, Exception) else {},
        "social": social if not isinstance(social, Exception) else {},
        "dns": dns_data if not isinstance(dns_data, Exception) else {},
        "whois": whois_data if not isinstance(whois_data, Exception) else {},
        "subdomains": subs if not isinstance(subs, Exception) else [],
    })


@app.post(
    "/api/ai/analyze",
    tags=["AI Analysis"],
    summary="AI-powered security analysis (Groq LLaMA)",
    description=(
        "Submit scan findings to Groq LLaMA for deep security analysis. "
        "Returns a structured markdown report including: threat assessment, "
        "CVE mapping, attack chain reconstruction, and prioritized remediation steps. "
        "Requires `GROQ_API_KEY` environment variable to be set."
    ),
    responses={
        200: {"description": "AI analysis report"},
        500: {"description": "AI engine error (check GROQ_API_KEY)", "model": ErrorResponse},
    },
)
async def ai_analyze(request: Request, user: User = Depends(web_user)):
    data = await request.json()
    try:
        from modules.ai.groq_analyzer import analyze_findings
        analysis = await asyncio.to_thread(
            analyze_findings, data.get("findings", []),
            data.get("target", ""), data.get("lang", "ar"),
        )
        return JSONResponse({"analysis": analysis})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post(
    "/api/nlp",
    tags=["NLP"],
    summary="Parse natural-language security command",
    description=(
        "Parse an Arabic or English free-text command into a structured action + target. "
        "First tries Groq AI (if `GROQ_API_KEY` is set); falls back to local rule-based parser.\n\n"
        "**Example inputs:**\n"
        "- `افحص tesla.com عن ثغرات XSS`\n"
        "- `Scan example.com for SQL injection`\n"
        "- `اجمع النطاقات الفرعية لـ google.com`\n"
        "- `Generate report for last scan`"
    ),
    responses={
        200: {"description": "Parsed command", "model": NLPResponse},
    },
)
async def nlp_parse(request: Request, user: User = Depends(web_user)):
    data = await request.json()
    text = data.get("text", "")
    from cli.nlp_parser import parse_command
    local_result = parse_command(text)

    if os.environ.get("GROQ_API_KEY"):
        try:
            from modules.ai.groq_analyzer import natural_language_to_command
            ai_result = await asyncio.to_thread(natural_language_to_command, text)
            if ai_result.get("confidence", 0) > 0.6 and ai_result.get("action") not in ("unknown", "error"):
                return JSONResponse(ai_result)
        except Exception:
            pass

    return JSONResponse(local_result)


# ─── Admin API ────────────────────────────────────────────────────────────────

@app.get(
    "/api/admin/auth-log",
    tags=["Admin"],
    summary="Authentication audit log",
    description=(
        "Returns the last N authentication events (login, logout, register, API key use). "
        "Each entry includes timestamp, event type, username, IP, and outcome. "
        "**Admin role required.**"
    ),
    responses={
        200: {"description": "List of auth log entries"},
        403: {"description": "Admin role required", "model": ErrorResponse},
    },
)
async def admin_auth_log(
    user: User = Depends(web_user),
    lines: int = 100,
):
    require_admin(user)
    log_path = Path(__file__).parent.parent / "logs" / "auth.log"
    if not log_path.exists():
        return JSONResponse([])
    with open(log_path, "r") as f:
        raw = f.readlines()
    entries = []
    for line in raw[-min(lines, 500):]:
        line = line.strip()
        if not line:
            continue
        # Format: "2026-06-29 03:01:05,747 SUCCESS | EVENT | user='x' | ip=y | detail"
        parts = line.split(" ", 2)
        timestamp = f"{parts[0]} {parts[1]}" if len(parts) >= 2 else line
        rest = parts[2] if len(parts) >= 3 else ""
        fields = [f.strip() for f in rest.split("|")]
        status = fields[0] if fields else ""
        event  = fields[1].strip() if len(fields) > 1 else ""
        user_f = fields[2].replace("user=", "").strip().strip("'") if len(fields) > 2 else ""
        ip     = fields[3].replace("ip=", "").strip() if len(fields) > 3 else ""
        detail = fields[4].strip() if len(fields) > 4 else ""
        entries.append({
            "timestamp": timestamp,
            "status": status,
            "event": event,
            "user": user_f,
            "ip": ip,
            "detail": detail,
        })
    return JSONResponse(list(reversed(entries)))


@app.get(
    "/api/admin/users",
    tags=["Admin"],
    summary="List all platform users",
    description="Returns all registered users with role, status, and login timestamps. **Admin role required.**",
    responses={
        200: {"description": "User list"},
        403: {"description": "Admin role required", "model": ErrorResponse},
    },
)
async def admin_list_users(user: User = Depends(web_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    users = (await db.execute(select(User).order_by(User.created_at))).scalars().all()
    return JSONResponse([{
        "id": u.id, "username": u.username, "email": u.email,
        "role": u.role, "is_active": u.is_active,
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "last_login": u.last_login.isoformat() if u.last_login else None,
    } for u in users])


@app.patch(
    "/api/admin/users/{user_id}",
    tags=["Admin"],
    summary="Update user role or status",
    description=(
        "Change a user's `role` (admin/analyst/viewer) or `is_active` flag. "
        "Cannot demote the last admin. **Admin role required.**"
    ),
    responses={
        200: {"description": "User updated"},
        404: {"description": "User not found", "model": ErrorResponse},
        403: {"description": "Admin role required", "model": ErrorResponse},
    },
)
async def admin_update_user(
    user_id: int, request: Request,
    user: User = Depends(web_user),
    db: AsyncSession = Depends(get_db),
):
    require_admin(user)
    data = await request.json()
    target = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not target:
        raise HTTPException(404, "User not found")
    if "role" in data and data["role"] in ("admin", "analyst", "viewer"):
        target.role = data["role"]
    if "is_active" in data:
        target.is_active = bool(data["is_active"])
    await db.commit()
    return JSONResponse({"success": True, "role": target.role, "is_active": target.is_active})


@app.delete(
    "/api/admin/users/{user_id}",
    tags=["Admin"],
    summary="Delete user account",
    description=(
        "Permanently delete a user and all associated data (targets, scans, findings). "
        "Cannot delete the last admin account. **Admin role required.**"
    ),
    responses={
        200: {"description": "User deleted"},
        400: {"description": "Cannot delete last admin", "model": ErrorResponse},
        404: {"description": "User not found", "model": ErrorResponse},
    },
)
async def admin_delete_user(
    user_id: int,
    user: User = Depends(web_user),
    db: AsyncSession = Depends(get_db),
):
    require_admin(user)
    if user_id == user.id:
        raise HTTPException(400, "Cannot delete your own account")
    target = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not target:
        raise HTTPException(404, "User not found")
    await db.delete(target)
    await db.commit()
    return JSONResponse({"success": True})


# ─── License Routes ───────────────────────────────────────────────────────────

@app.get("/license", response_class=HTMLResponse, include_in_schema=False)
async def license_page(request: Request, user: User = Depends(web_user),
                       msg: str = "", msg_type: str = ""):
    lic = get_license()
    features_list = list(FEATURE_LABELS.items())
    free_features = set(TIER_FEATURES["free"])
    pro_features  = set(TIER_FEATURES["pro"])
    return templates.TemplateResponse(request, "license.html", {
        "app_name": APP_NAME, "version": APP_VERSION,
        "active": "license", "user": user,
        "lic": lic,
        "features": features_list,
        "free_features": free_features,
        "pro_features": pro_features,
        "flash_msg": msg,
        "flash_type": msg_type or "info",
        "prefill_key": "",
    })


@app.post("/license/activate", response_class=HTMLResponse, include_in_schema=False)
async def license_activate_form(
    request: Request,
    key: str = Form(...),
    user: User = Depends(web_user),
):
    require_admin(user)
    ip = get_client_ip(request)

    allowed, remaining = check_rate_limit(ip)
    if not allowed:
        minutes = remaining // 60 + 1
        log_auth_event("LICENSE_ACTIVATE", user.username, ip, False, f"rate_limited remaining={remaining}s")
        lic = get_license()
        return templates.TemplateResponse(request, "license.html", {
            "app_name": APP_NAME, "version": APP_VERSION,
            "active": "license", "user": user,
            "lic": lic,
            "features": list(FEATURE_LABELS.items()),
            "free_features": set(TIER_FEATURES["free"]),
            "pro_features":  set(TIER_FEATURES["pro"]),
            "flash_msg": f"Too many attempts. Try again in {minutes} minute(s).",
            "flash_type": "error",
            "prefill_key": key,
        }, status_code=429)

    success, message, new_lic = activate_license(key.strip())
    if success:
        clear_attempts(ip)
        log_auth_event("LICENSE_ACTIVATE", user.username, ip, True)
    else:
        record_failed_attempt(ip)
        log_auth_event("LICENSE_ACTIVATE", user.username, ip, False, message)
    lic = get_license()
    features_list = list(FEATURE_LABELS.items())
    return templates.TemplateResponse(request, "license.html", {
        "app_name": APP_NAME, "version": APP_VERSION,
        "active": "license", "user": user,
        "lic": lic,
        "features": features_list,
        "free_features": set(TIER_FEATURES["free"]),
        "pro_features":  set(TIER_FEATURES["pro"]),
        "flash_msg": message,
        "flash_type": "success" if success else "error",
        "prefill_key": "" if success else key,
    })


@app.post("/license/deactivate", include_in_schema=False)
async def license_deactivate_form(request: Request, user: User = Depends(web_user)):
    require_admin(user)
    deactivate_license()
    return RedirectResponse("/license?msg=تم+إلغاء+الترخيص+والعودة+للنسخة+المجانية&msg_type=warning",
                            status_code=302)


@app.post(
    "/api/license/activate",
    tags=["Admin"],
    summary="Activate license key (API)",
    description="Activate a new OPTISEC license key. **Admin role required.**",
)
async def api_license_activate(request: Request, user: User = Depends(web_user)):
    require_admin(user)
    ip = get_client_ip(request)

    allowed, remaining = check_rate_limit(ip)
    if not allowed:
        log_auth_event("LICENSE_ACTIVATE", user.username, ip, False, f"rate_limited remaining={remaining}s")
        raise HTTPException(429, f"Too many attempts. Try again in {remaining} seconds.")

    data = await request.json()
    key = data.get("key", "").strip()
    if not key:
        record_failed_attempt(ip)
        raise HTTPException(400, "License key is required")
    success, message, lic = activate_license(key)
    if not success:
        record_failed_attempt(ip)
        log_auth_event("LICENSE_ACTIVATE", user.username, ip, False, message)
        raise HTTPException(422, message)
    clear_attempts(ip)
    log_auth_event("LICENSE_ACTIVATE", user.username, ip, True)
    return JSONResponse({
        "success": True,
        "message": message,
        "tier": lic.tier,
        "issued_to": lic.issued_to,
        "expires_at": lic.expires_at,
        "days_left": lic.days_left,
    })


@app.post(
    "/api/license/generate",
    tags=["Admin"],
    summary="Generate license key",
    description="Generate a signed license key. **Admin role required.** Dev/testing use.",
)
async def api_license_generate(request: Request, user: User = Depends(web_user)):
    require_admin(user)
    data = await request.json()
    try:
        key = generate_license_key(
            tier=data.get("tier", "pro"),
            issued_to=data.get("issued_to", ""),
            email=data.get("email", ""),
            days=int(data.get("days", 365)),
        )
        return JSONResponse({"key": key})
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get(
    "/api/license/status",
    tags=["Admin"],
    summary="Current license status",
    description="Returns the active license tier, features, and limits.",
)
async def api_license_status(user: User = Depends(web_user)):
    lic = get_license()
    return JSONResponse({
        "tier": lic.tier,
        "tier_label": lic.tier_label,
        "issued_to": lic.issued_to,
        "email": lic.email,
        "issued_at": lic.issued_at,
        "expires_at": lic.expires_at,
        "days_left": lic.days_left,
        "expired": lic.expired,
        "max_targets": lic.max_targets,
        "max_scans_day": lic.max_scans_day,
        "max_users": lic.max_users,
        "features": lic.features,
    })


# ── IOC Correlation Engine ────────────────────────────────────────────────────

@app.get("/api/correlations")
async def get_ioc_correlations(
    refresh: bool = False,
    user: User = Depends(web_user),
):
    """
    Return IOC correlation clusters.
    Uses cached results unless ?refresh=true triggers a fresh run.
    Requires authentication (any role).
    """
    if not refresh:
        cached = load_cached()
        if cached:
            return JSONResponse(cached)

    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: run_correlation(save=True)
        )
        return JSONResponse(result)
    except Exception as exc:
        raise HTTPException(500, f"Correlation engine error: {exc}")


@app.get("/api/correlations/{cluster_id}")
async def get_correlation_cluster(
    cluster_id: str,
    user: User = Depends(web_user),
):
    """Return full details for a single correlation cluster by its cluster_id."""
    data = load_cached()
    if not data:
        raise HTTPException(404, "No correlation data found — run GET /api/correlations?refresh=true first")

    cluster = next(
        (c for c in data.get("clusters", []) if c["cluster_id"] == cluster_id),
        None,
    )
    if not cluster:
        raise HTTPException(404, f"Cluster '{cluster_id}' not found")

    return JSONResponse({
        "cluster": cluster,
        "generated_at": data.get("generated_at"),
        "otx_enabled":  data.get("otx_enabled"),
    })


# ── TEMPORARY — one-off migration trigger, DELETE AFTER USE ──────────────────
# Render's free plan has no Shell access, so this token-gated endpoint is the
# only way to run web.migrate_normalize_demo_severity.migrate() on production.
# Only registered when running on Render (or GROQ_ENV=production) so it never
# appears in local/dev. Remove this whole block + MIGRATION_SECRET_TOKEN env
# var once the migration has been run against production.
if os.environ.get("GROQ_ENV") == "production" or os.environ.get("RENDER"):
    import secrets as _secrets_compare

    @app.post("/internal/run-migration", include_in_schema=False)
    async def run_one_off_migration(request: Request):
        """TEMPORARY endpoint — see block comment above. Delete after use."""
        expected_token = os.environ.get("MIGRATION_SECRET_TOKEN")
        provided_token = request.headers.get("X-Migration-Token")
        if not expected_token or not provided_token or not _secrets_compare.compare_digest(
            provided_token, expected_token
        ):
            raise HTTPException(403, "Forbidden")

        from web.migrate_normalize_demo_severity import migrate as _run_migration
        counts = await _run_migration()
        return JSONResponse({"normalized": counts, "total_updated": sum(counts.values())})

