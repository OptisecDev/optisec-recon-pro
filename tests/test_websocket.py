"""Tests for /ws/scan/{scan_id} auth + ownership (IDOR fix).

Previously this endpoint accepted every WebSocket handshake with no
identity check and no scan-ownership check, so anyone who knew or guessed
a scan_id could stream another user's live scan results. These tests drive
the real app (web/app.py) through FastAPI's TestClient WebSocket support,
with `get_db` overridden to an isolated in-memory SQLite DB so nothing
touches the dev database file.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from starlette.websockets import WebSocketDisconnect
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from web.database import Base, get_db
from web.models import User, Scan
from web.auth import create_access_token, hash_password
from web.websocket_manager import MAX_CONNECTIONS_PER_USER
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
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    _run(_setup())

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app_module.app.dependency_overrides[get_db] = override_get_db

    # Deliberately not `with TestClient(...) as c:` — entering the context
    # manager fires the app's real startup hook (init_db against the real
    # DB file, darkweb scheduler, honeypot listeners), which is both slow
    # and irrelevant here. A bare TestClient still serves individual
    # requests/websocket connections without running lifespan events,
    # matching tests/test_migration_endpoint.py's convention.
    c = TestClient(app_module.app)
    yield SimpleFixture(c, session_factory)

    app_module.app.dependency_overrides.pop(get_db, None)
    _run(engine.dispose())


class SimpleFixture:
    """Bundles the TestClient with helpers that seed data via the same DB."""

    def __init__(self, client: TestClient, session_factory):
        self.client = client
        self._session_factory = session_factory

    def websocket_connect(self, url):
        return self.client.websocket_connect(url)

    def seed_user(self, username: str, role: str = "viewer") -> tuple:
        async def go():
            async with self._session_factory() as db:
                user = User(
                    username=username, email=f"{username}@example.com",
                    password_hash=hash_password("Passw0rd!1"),
                    role=role, is_active=True,
                )
                db.add(user)
                await db.commit()
                await db.refresh(user)
                return user.id
        user_id = _run(go())
        token = create_access_token(user_id, role)
        return user_id, token

    def seed_scan(self, scan_id: str, owner_id: int, status: str = "running", progress: int = 10) -> None:
        async def go():
            async with self._session_factory() as db:
                db.add(Scan(
                    id=scan_id, user_id=owner_id, target_url="http://example.com",
                    scan_types=["dns"], status=status, progress=progress,
                ))
                await db.commit()
        _run(go())


class TestWebSocketAuthentication:
    def test_rejects_connection_without_token(self, client):
        client.seed_user("owner_no_token")
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws/scan/some-scan-id"):
                pass
        assert exc_info.value.code == 1008

    def test_rejects_connection_with_garbage_token(self, client):
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws/scan/some-scan-id?token=not-a-real-jwt"):
                pass
        assert exc_info.value.code == 1008


class TestWebSocketAuthorization:
    def test_rejects_token_valid_but_scan_belongs_to_another_user(self, client):
        owner_id, _ = client.seed_user("owner_a")
        _, attacker_token = client.seed_user("attacker_a")
        client.seed_scan("scan-owned-by-owner-a", owner_id)

        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect(f"/ws/scan/scan-owned-by-owner-a?token={attacker_token}"):
                pass
        assert exc_info.value.code == 1008

    def test_rejects_unknown_scan_id(self, client):
        _, token = client.seed_user("owner_b")
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect(f"/ws/scan/does-not-exist?token={token}"):
                pass
        assert exc_info.value.code == 1008

    def test_accepts_valid_token_and_matching_ownership(self, client):
        owner_id, owner_token = client.seed_user("owner_c")
        client.seed_scan("scan-owned-by-owner-c", owner_id, status="running", progress=42)

        with client.websocket_connect(f"/ws/scan/scan-owned-by-owner-c?token={owner_token}") as ws:
            msg = ws.receive_json()
            assert msg["type"] == "state"
            assert msg["status"] == "running"
            assert msg["progress"] == 42

    def test_admin_can_view_any_users_scan(self, client):
        owner_id, _ = client.seed_user("owner_d")
        _, admin_token = client.seed_user("admin_d", role="admin")
        client.seed_scan("scan-owned-by-owner-d", owner_id)

        with client.websocket_connect(f"/ws/scan/scan-owned-by-owner-d?token={admin_token}") as ws:
            msg = ws.receive_json()
            assert msg["type"] == "state"


class TestWebSocketConnectionLimit:
    def test_rejects_beyond_max_concurrent_connections_per_user(self, client):
        owner_id, token = client.seed_user("owner_e")
        client.seed_scan("scan-e", owner_id)

        sockets = []
        try:
            for _ in range(MAX_CONNECTIONS_PER_USER):
                ws = client.websocket_connect(f"/ws/scan/scan-e?token={token}").__enter__()
                sockets.append(ws)

            with pytest.raises(WebSocketDisconnect) as exc_info:
                with client.websocket_connect(f"/ws/scan/scan-e?token={token}"):
                    pass
            assert exc_info.value.code == 1008
        finally:
            for ws in sockets:
                ws.close()
