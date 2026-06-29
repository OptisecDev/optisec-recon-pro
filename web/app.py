import sys
import os
import asyncio
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import (
    FastAPI, Request, Form, HTTPException, BackgroundTasks,
    Depends, WebSocket, WebSocketDisconnect,
)
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from web.database import get_db, init_db, SessionLocal
from web.models import User, Target, Scan, Finding, Report
from web.auth import (
    verify_password, hash_password, create_access_token,
    generate_api_key, get_current_user,
    require_admin, require_analyst_or_admin,
    check_rate_limit, record_failed_attempt, clear_attempts,
    log_auth_event, validate_password_strength,
    SECRET_KEY, ALGORITHM,
)
from web.websocket_manager import ws_manager

from modules.recon.subdomains import enumerate_subdomains
from modules.recon.dns_lookup import dns_lookup
from modules.recon.whois_lookup import whois_lookup
from modules.recon.nmap_scanner import nmap_scan
from modules.vuln.xss import scan_xss
from modules.vuln.sqli import scan_sqli
from modules.vuln.ssrf import scan_ssrf
from modules.vuln.lfi import scan_lfi
from modules.vuln.open_redirect import scan_open_redirect
from modules.osint.email_finder import find_emails
from modules.osint.social_media import find_social_profiles
from modules.report.pdf_generator import generate_report
from config import APP_NAME, APP_VERSION, REPORTS_DIR
from web.routers import bug_bounty, compliance, firewall, vpn, ai_security, quantum, federation, osint as osint_router
from web.routers import attack_navigator, darkweb, autonomous_rt, ngfw, threat_feed
from modules.ioc_correlation import run_correlation, load_cached

BASE_DIR = Path(__file__).parent

app = FastAPI(title=APP_NAME, version=APP_VERSION)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

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
app.include_router(autonomous_rt.router)
app.include_router(ngfw.router)
app.include_router(threat_feed.router)


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
    await _ensure_first_admin()


async def _ensure_first_admin():
    async with SessionLocal() as db:
        count = (await db.execute(select(func.count()).select_from(User))).scalar()
        if count == 0:
            import secrets as _secrets
            username = os.environ.get("FIRST_ADMIN_USER", "admin")
            password = os.environ.get("FIRST_ADMIN_PASSWORD") or (
                _secrets.token_urlsafe(12) + "!A1"  # meets strength requirements
            )
            email = os.environ.get("FIRST_ADMIN_EMAIL", "admin@optisec.local")
            admin = User(
                username=username,
                email=email,
                password_hash=hash_password(password),
                role="admin",
                api_key=generate_api_key(),
                is_active=True,
            )
            db.add(admin)
            await db.commit()
            print(f"[OPTISEC] Initial admin created → {username} / {password}")
            log_auth_event("INIT_ADMIN", username, "localhost", True, "first admin created")


# ─── Exception Handlers ───────────────────────────────────────────────────────

@app.exception_handler(HTTPException)
async def on_http_exception(request: Request, exc: HTTPException):
    if exc.status_code == 401 and not request.url.path.startswith("/api/"):
        return RedirectResponse(f"/login?next={request.url.path}", status_code=302)
    if exc.status_code == 403 and not request.url.path.startswith("/api/"):
        return templates.TemplateResponse(request, "error.html", {
            "app_name": APP_NAME, "error": "Access denied", "code": 403
        }, status_code=403)
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)


# ─── Auth Dependency ──────────────────────────────────────────────────────────

async def web_user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


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
    ip = request.client.host if request.client else "unknown"

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
    ip = request.client.host if request.client else "unknown"

    pw_errors = validate_password_strength(password)
    if pw_errors:
        return templates.TemplateResponse(request, "register.html", {
            "app_name": APP_NAME,
            "error": "Password must have: " + ", ".join(pw_errors),
        }, status_code=400)

    exists = (await db.execute(
        select(User).where((User.username == username) | (User.email == email))
    )).scalar_one_or_none()
    if exists:
        return templates.TemplateResponse(request, "register.html", {
            "app_name": APP_NAME, "error": "Username or email already taken",
        }, status_code=400)

    count = (await db.execute(select(func.count()).select_from(User))).scalar()
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role="admin" if count == 0 else "viewer",
        api_key=generate_api_key(),
        is_active=True,
    )
    db.add(user)
    await db.commit()
    log_auth_event("REGISTER", username, ip, True)

    token = create_access_token(user.id, user.role)
    response = RedirectResponse("/", status_code=302)
    response.set_cookie("access_token", token, httponly=True, max_age=1800, samesite="lax")
    return response


@app.get("/logout")
async def logout(request: Request):
    ip = request.client.host if request.client else "unknown"
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

@app.post("/api/auth/login")
async def api_login(request: Request, db: AsyncSession = Depends(get_db)):
    data = await request.json()
    ip = request.client.host if request.client else "unknown"
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


@app.post("/api/auth/register")
async def api_register(request: Request, db: AsyncSession = Depends(get_db)):
    data = await request.json()
    username = data.get("username", "")
    email = data.get("email", "")
    password = data.get("password", "")
    ip = request.client.host if request.client else "unknown"

    pw_errors = validate_password_strength(password)
    if pw_errors:
        raise HTTPException(400, "Password must have: " + ", ".join(pw_errors))

    if (await db.execute(select(User).where(
        (User.username == username) | (User.email == email)
    ))).scalar_one_or_none():
        raise HTTPException(400, "Username or email already taken")

    count = (await db.execute(select(func.count()).select_from(User))).scalar()
    user = User(
        username=username, email=email,
        password_hash=hash_password(password),
        role="admin" if count == 0 else "viewer",
        api_key=generate_api_key(),
    )
    db.add(user)
    await db.commit()
    log_auth_event("API_REGISTER", username, ip, True)
    return JSONResponse({"id": user.id, "username": user.username,
                         "role": user.role, "api_key": user.api_key})


@app.post("/api/auth/api-key/regenerate")
async def regenerate_api_key(
    user: User = Depends(web_user),
    db: AsyncSession = Depends(get_db),
):
    user.api_key = generate_api_key()
    await db.commit()
    await db.refresh(user)
    return JSONResponse({"api_key": user.api_key})


# ─── Web Pages ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, user: User = Depends(web_user), db: AsyncSession = Depends(get_db)):
    target_count = (await db.execute(
        select(func.count()).select_from(Target).where(Target.user_id == user.id)
    )).scalar()
    scan_count = (await db.execute(
        select(func.count()).select_from(Scan).where(Scan.user_id == user.id)
    )).scalar()
    finding_count = (await db.execute(
        select(func.count()).select_from(Finding).join(Scan).where(Scan.user_id == user.id)
    )).scalar()
    recent_scans = (await db.execute(
        select(Scan).where(Scan.user_id == user.id)
        .order_by(Scan.created_at.desc()).limit(5)
    )).scalars().all()

    return templates.TemplateResponse(request, "index.html", {
        "app_name": APP_NAME, "version": APP_VERSION,
        "active": "home", "user": user,
        "target_count": target_count,
        "scan_count": scan_count,
        "finding_count": finding_count,
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


@app.post("/targets/add")
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


@app.delete("/targets/{target_id}")
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
    total_findings = (await db.execute(select(func.count()).select_from(Finding))).scalar()
    return templates.TemplateResponse(request, "admin.html", {
        "app_name": APP_NAME, "active": "admin", "user": user,
        "users": users, "total_scans": total_scans, "total_findings": total_findings,
    })


# ─── Scan API ─────────────────────────────────────────────────────────────────

@app.post("/api/scan")
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


@app.get("/api/scan/{scan_id}")
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


@app.get("/api/scans")
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


@app.get("/api/findings")
async def list_findings(user: User = Depends(web_user), db: AsyncSession = Depends(get_db)):
    findings = (await db.execute(
        select(Finding).join(Scan).where(Scan.user_id == user.id)
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

        results["vulnerabilities"] = all_vulns

        async with SessionLocal() as db:
            for v in all_vulns:
                db.add(Finding(
                    scan_id=scan_id, target_id=target_id,
                    vuln_type=v.get("type", "Unknown"),
                    severity=v.get("severity", "Medium"),
                    url=v.get("url", ""),
                    parameter=v.get("parameter", ""),
                    payload=v.get("payload", ""),
                    evidence=v.get("evidence", ""),
                ))
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
    await ws_manager.connect(scan_id, websocket)
    try:
        scan = await db.get(Scan, scan_id)
        if scan:
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
        ws_manager.disconnect(scan_id, websocket)


# ─── Scanner Upgrade APIs ─────────────────────────────────────────────────────

@app.post("/api/scan/ssl")
async def scan_ssl(request: Request, user: User = Depends(web_user)):
    data = await request.json()
    target = data.get("target", "").strip()
    if not target:
        raise HTTPException(400, "Target is required")
    from modules.recon.ssl_analysis import analyze_ssl
    result = await asyncio.to_thread(analyze_ssl, target)
    return JSONResponse(result)


@app.post("/api/scan/headers")
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


@app.post("/api/scan/ports")
async def scan_ports(request: Request, user: User = Depends(web_user)):
    data = await request.json()
    target = data.get("target", "").strip()
    if not target:
        raise HTTPException(400, "Target is required")
    from modules.recon.port_scanner import scan_ports as do_scan
    result = await asyncio.to_thread(do_scan, target)
    return JSONResponse(result)


# ─── Report API ───────────────────────────────────────────────────────────────

@app.post("/api/report")
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

@app.post("/api/osint")
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


@app.post("/api/ai/analyze")
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


@app.post("/api/nlp")
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

@app.get("/api/admin/auth-log")
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


@app.get("/api/admin/users")
async def admin_list_users(user: User = Depends(web_user), db: AsyncSession = Depends(get_db)):
    require_admin(user)
    users = (await db.execute(select(User).order_by(User.created_at))).scalars().all()
    return JSONResponse([{
        "id": u.id, "username": u.username, "email": u.email,
        "role": u.role, "is_active": u.is_active,
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "last_login": u.last_login.isoformat() if u.last_login else None,
    } for u in users])


@app.patch("/api/admin/users/{user_id}")
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


@app.delete("/api/admin/users/{user_id}")
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


# ── IOC Correlation Engine ────────────────────────────────────────────────────

@app.get("/api/correlations")
async def get_ioc_correlations(
    refresh: bool = False,
    user: User = Depends(get_current_user),
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
    user: User = Depends(get_current_user),
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
