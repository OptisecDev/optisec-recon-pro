"""
One-click demo login is opt-in via DEMO_ENABLED (config.py, default false).

With DEMO_ENABLED unset/false:
  - GET /demo returns 404 and sets no access_token session cookie, even if a
    "demo" user already exists in the DB.
  - _startup_db_sequence() never calls _ensure_demo_account(), so startup
    neither creates nor touches the demo account.

With DEMO_ENABLED=true the previous behaviour is unchanged: /demo issues a
session for the active demo user and startup seeds the account.
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
from web.models import User
from web.auth import hash_password
import web.app as app_module


def _run(coro):
    return asyncio.run(coro)


def test_demo_enabled_defaults_to_false():
    # Fresh interpreter rather than importlib.reload(config): reloading would
    # regenerate config's dev-time secrets under every other test's feet.
    import subprocess
    env = {k: v for k, v in os.environ.items() if k != "DEMO_ENABLED"}
    env.setdefault("GROQ_ENV", "development")
    out = subprocess.run(
        [sys.executable, "-c", "import config; print(config.DEMO_ENABLED)"],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        env=env, capture_output=True, text=True, check=True,
    )
    assert out.stdout.strip().splitlines()[-1] == "False"


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
        async with session_factory() as session:
            session.add(User(
                username="demo",
                email="demo@optisec.local",
                password_hash=hash_password("not-used-in-this-test"),
                role="analyst",
                is_active=True,
            ))
            await session.commit()

    _run(_setup())

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app_module.app.dependency_overrides[get_db] = override_get_db
    c = TestClient(app_module.app)
    yield c
    app_module.app.dependency_overrides.pop(get_db, None)
    _run(engine.dispose())


def test_demo_route_returns_404_when_disabled(client, monkeypatch):
    monkeypatch.setattr(app_module, "DEMO_ENABLED", False)
    resp = client.get("/demo", follow_redirects=False)
    assert resp.status_code == 404
    assert "access_token" not in resp.cookies
    assert "access_token" not in resp.headers.get("set-cookie", "")


def test_demo_route_issues_session_when_enabled(client, monkeypatch):
    monkeypatch.setattr(app_module, "DEMO_ENABLED", True)
    resp = client.get("/demo", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/"
    assert "access_token" in resp.cookies


def _patch_startup_sequence(monkeypatch, calls):
    async def _noop():
        return None

    async def _has_col():
        return True

    async def _admin():
        calls.append("admin")

    async def _demo():
        calls.append("demo")

    monkeypatch.setattr(app_module, "init_db", _noop)
    # The scan-authz column migration only exists on branches that carry the
    # scan authorization feature; stub it out when present so startup never
    # touches a real database, but don't require it.
    try:
        import web.migrate_add_scan_authz_columns as scan_authz_migration
    except ImportError:
        scan_authz_migration = None
    if scan_authz_migration is not None:
        monkeypatch.setattr(scan_authz_migration, "migrate", _noop)
    try:
        import web.migrate_add_user_token_version as token_version_migration
    except ImportError:
        token_version_migration = None
    if token_version_migration is not None:
        monkeypatch.setattr(token_version_migration, "migrate", _noop)
    monkeypatch.setattr(app_module, "_users_table_has_api_key_hash", _has_col)
    monkeypatch.setattr(app_module, "_ensure_first_admin", _admin)
    monkeypatch.setattr(app_module, "_ensure_demo_account", _demo)


def test_startup_skips_demo_account_when_disabled(monkeypatch):
    calls = []
    _patch_startup_sequence(monkeypatch, calls)
    monkeypatch.setattr(app_module, "DEMO_ENABLED", False)
    _run(app_module._startup_db_sequence())
    assert calls == ["admin"]


def test_startup_seeds_demo_account_when_enabled(monkeypatch):
    calls = []
    _patch_startup_sequence(monkeypatch, calls)
    monkeypatch.setattr(app_module, "DEMO_ENABLED", True)
    _run(app_module._startup_db_sequence())
    assert calls == ["admin", "demo"]
