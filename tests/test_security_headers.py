"""
Tests for web.app.security_headers_middleware, added after an OWASP ZAP
baseline DAST pass against the live deployment flagged several standard
security response headers as missing (X-Content-Type-Options,
X-Frame-Options/anti-clickjacking, Strict-Transport-Security,
Permissions-Policy), plus the Content-Security-Policy header (script-src
nonce-based, no unsafe-inline; style-src still unsafe-inline -- see the
comment above _build_csp in web/app.py for why).

COOP/COEP/CORP are still deliberately out of scope -- not asserted here.

Same TestClient + in-memory-SQLite fixture pattern as
tests/test_register_rate_limit.py.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from web.database import Base, get_db
import web.app as app_module


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def client():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    TestSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    _run(_setup())

    async def _get_db_override():
        async with TestSessionLocal() as session:
            yield session

    app_module.app.dependency_overrides[get_db] = _get_db_override
    test_client = TestClient(app_module.app)
    yield test_client
    app_module.app.dependency_overrides.clear()
    _run(engine.dispose())


def test_content_type_options_and_frame_options_always_set(client):
    resp = client.get("/login")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"


def test_csp_denies_by_default_and_allowlists_only_jsdelivr(client):
    resp = client.get("/login")
    csp = resp.headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp
    assert "base-uri 'self'" in csp
    assert "form-action 'self'" in csp
    # The only third-party origin the app actually loads anywhere.
    assert "https://cdn.jsdelivr.net" in csp
    # No eval-requiring code anywhere in the frontend, so this must stay out.
    assert "unsafe-eval" not in csp


def test_script_src_has_no_unsafe_inline(client):
    # The addEventListener refactor (main.js's optisecDispatch + every
    # template's data-on*/-args/-event attributes) removed the need for
    # 'unsafe-inline' on inline on*= attributes, and a per-request nonce
    # (request.state.csp_nonce, read by every template's <script> tag)
    # covers the templates' own inline <script> block content -- so
    # script-src should carry neither 'unsafe-inline' nor a static nonce.
    resp = client.get("/login")
    csp = resp.headers["Content-Security-Policy"]
    script_src = [d for d in csp.split("; ") if d.startswith("script-src")][0]
    assert "'unsafe-inline'" not in script_src
    assert "'nonce-" in script_src


def test_style_src_still_has_unsafe_inline(client):
    # Inline style="" attributes and <style> blocks are pervasive across
    # every template -- removing this needs a separate CSS-class extraction
    # refactor, not covered by the addEventListener work.
    resp = client.get("/login")
    csp = resp.headers["Content-Security-Policy"]
    style_src = [d for d in csp.split("; ") if d.startswith("style-src")][0]
    assert "'unsafe-inline'" in style_src


def test_csp_nonce_is_random_per_request(client):
    csp1 = client.get("/login").headers["Content-Security-Policy"]
    csp2 = client.get("/login").headers["Content-Security-Policy"]
    nonce1 = csp1.split("'nonce-")[1].split("'")[0]
    nonce2 = csp2.split("'nonce-")[1].split("'")[0]
    assert nonce1 != nonce2


def test_csp_nonce_matches_the_rendered_page(client):
    # /login itself has no inline <script> of its own (base.html only pulls
    # in /static/js/main.js, an external same-origin file that doesn't need
    # a nonce) -- /landing does and needs no auth, so use that instead.
    resp = client.get("/landing")
    csp_nonce = resp.headers["Content-Security-Policy"].split("'nonce-")[1].split("'")[0]
    assert f'nonce="{csp_nonce}"' in resp.text


def test_csp_set_on_every_response_not_just_templated_pages(client):
    # /docs and /redoc build raw HTMLResponse strings, not TemplateResponse —
    # confirm the middleware still covers them.
    for path in ("/login", "/register", "/docs", "/redoc"):
        resp = client.get(path)
        assert "Content-Security-Policy" in resp.headers


def test_docs_inline_script_nonce_matches_csp_header(client):
    # /docs's SwaggerUIBundle init script is a raw HTMLResponse f-string,
    # not a Jinja template -- separate code path from the other pages,
    # worth its own check.
    resp = client.get("/docs")
    csp_nonce = resp.headers["Content-Security-Policy"].split("'nonce-")[1].split("'")[0]
    assert f'nonce="{csp_nonce}"' in resp.text


def test_permissions_policy_set(client):
    resp = client.get("/login")
    policy = resp.headers["Permissions-Policy"]
    assert "geolocation=()" in policy
    assert "camera=()" in policy


def test_hsts_absent_outside_production(client, monkeypatch):
    monkeypatch.setattr(app_module, "IS_PRODUCTION", False)
    resp = client.get("/login")
    assert "Strict-Transport-Security" not in resp.headers


def test_hsts_present_in_production(client, monkeypatch):
    monkeypatch.setattr(app_module, "IS_PRODUCTION", True)
    resp = client.get("/login")
    assert resp.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"
