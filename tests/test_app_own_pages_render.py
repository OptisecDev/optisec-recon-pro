"""
Render-through-the-real-app coverage for the pages defined directly in
web/app.py (as opposed to web/routers/*.py, which
tests/test_shared_templates_globals.py already covers).

Added alongside the addEventListener/CSP-nonce refactor: main.js's
optisecDispatch replaced 261 inline on*= attributes across 26 templates
with data-on*/-args/-event attributes, and every template's own inline
<script> block picked up a nonce="{{ request.state.csp_nonce }}" so
script-src can drop 'unsafe-inline'. Some of the most heavily-edited
templates (osint.html: 43 handlers, index.html: 15, admin.html: Jinja
tojson-encoded args) aren't reachable through any existing test, so a
mechanical mistake in any of those files could pass CI silently. This
renders each one through the real app with a real authenticated user and
asserts: 200, well-formed HTML, and no on*= attribute or bare <script>
(without a nonce) survived in the output.

Same TestClient + in-memory-SQLite + _seed_user_token pattern as
tests/test_shared_templates_globals.py.
"""

import asyncio
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

import web.app as app_module
from web.database import Base, get_db
from web.models import User
from web.auth import create_access_token, hash_password

INLINE_HANDLER_RE = re.compile(
    r'(?<!data-)(?<!data-on)\bon(?:click|change|keydown|keyup|submit|input|error)="'
)
BARE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)(?![^>]*\bnonce=)[^>]*>")

# path -> role required (None = any authenticated user)
APP_OWN_PAGES = {
    "/": None,
    "/targets": None,
    "/scan": None,
    "/osint": None,
    "/reports": None,
    "/cve-pipeline": None,
    "/api-docs": None,
    "/license": None,
    "/admin": "admin",
}


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def client():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    _run(_setup())

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app_module.app.dependency_overrides[get_db] = override_get_db
    c = TestClient(app_module.app)
    yield c, session_factory
    app_module.app.dependency_overrides.pop(get_db, None)
    _run(engine.dispose())


def _seed_user_token(session_factory, username: str, role: str) -> str:
    async def go():
        async with session_factory() as db:
            user = User(
                username=username, email=f"{username}@example.com",
                password_hash=hash_password("Passw0rd!1"),
                role=role, subscription_tier="enterprise", is_active=True,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return user.id
    user_id = _run(go())
    return create_access_token(user_id, role)


@pytest.mark.parametrize("path,role", list(APP_OWN_PAGES.items()))
def test_page_renders_200_with_no_leftover_inline_handlers(client, path, role):
    c, session_factory = client
    token = _seed_user_token(session_factory, f"u_{abs(hash(path))}", role or "viewer")
    resp = c.get(path, cookies={"access_token": token})
    assert resp.status_code == 200, (
        f"{path} returned {resp.status_code}, expected 200. Body: {resp.text[:500]}"
    )
    assert "<html" in resp.text.lower()

    leftover = INLINE_HANDLER_RE.findall(resp.text)
    assert not leftover, f"{path} still has raw inline event handler attribute(s)"

    bare_scripts = BARE_SCRIPT_RE.findall(resp.text)
    assert not bare_scripts, f"{path} has a <script> with neither src= nor nonce=: {bare_scripts}"

    csp = resp.headers["Content-Security-Policy"]
    if "'nonce-" in csp:
        nonce = csp.split("'nonce-")[1].split("'")[0]
        for tag in re.findall(r"<script[^>]*>", resp.text):
            if " src=" not in tag:
                assert f'nonce="{nonce}"' in tag, f"{path}: inline script tag missing/mismatched nonce: {tag}"
