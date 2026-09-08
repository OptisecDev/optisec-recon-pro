"""
Query-count regression coverage for GET /targets (web/app.py targets_page).

Added during the Targets feature audit (2026-09-07 fix, see commit 91090b3):
the scan-count lookup used to run one SELECT per target in a Python loop
(an N+1), replaced with a single grouped query. This test counts the
actual SQL statements the route issues via a SQLAlchemy
`before_cursor_execute` event listener, and asserts the count stays flat
as the number of targets (and their scans) grows -- a regression back to
the per-target loop would make this test fail instead of silently
degrading page load time in production.

Own engine/fixture (rather than reusing tests/test_targets_idor.py's
`client` fixture) because it needs a direct handle on the underlying sync
engine to attach the event listener.
"""

import asyncio
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sqlalchemy import event
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

import web.app as app_module
from web.database import Base, get_db
from web.models import User, Target, Scan
from web.auth import create_access_token, hash_password


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def client_with_engine():
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
    yield c, session_factory, engine
    app_module.app.dependency_overrides.pop(get_db, None)
    _run(engine.dispose())


def _seed_user_token(session_factory, username: str) -> tuple:
    async def go():
        async with session_factory() as db:
            user = User(
                username=username, email=f"{username}@example.com",
                password_hash=hash_password("Passw0rd!1"),
                role="analyst", subscription_tier="enterprise", is_active=True,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return user.id
    user_id = _run(go())
    return user_id, create_access_token(user_id, "analyst")


def _seed_targets_with_scans(session_factory, user_id: int, count: int, scans_per_target: int = 2):
    async def go():
        async with session_factory() as db:
            for i in range(count):
                t = Target(user_id=user_id, url=f"https://n1-target-{uuid.uuid4().hex[:8]}.example", name="", notes="")
                db.add(t)
                await db.flush()
                for _ in range(scans_per_target):
                    db.add(Scan(
                        id=uuid.uuid4().hex, target_id=t.id, user_id=user_id,
                        target_url=t.url, scan_types=["dns"], status="done",
                    ))
            await db.commit()
    _run(go())


def _count_queries(engine, fn):
    """Run fn() and return the number of SQL statements executed against
    engine's underlying sync connection while it ran."""
    counter = {"n": 0}

    def _before_cursor_execute(*args, **kwargs):
        counter["n"] += 1

    sync_engine = engine.sync_engine
    event.listen(sync_engine, "before_cursor_execute", _before_cursor_execute)
    try:
        fn()
    finally:
        event.remove(sync_engine, "before_cursor_execute", _before_cursor_execute)
    return counter["n"]


def test_targets_page_query_count_does_not_scale_with_target_count(client_with_engine):
    """The number of SQL statements GET /targets issues must stay constant
    as the target count grows -- a linear increase means the N+1
    (per-target scan-count SELECT in a loop) has regressed."""
    c, session_factory, engine = client_with_engine
    owner_id, owner_token = _seed_user_token(session_factory, "n1owner")
    cookies = {"access_token": owner_token}

    def hit_targets_page():
        resp = c.get("/targets", cookies=cookies)
        assert resp.status_code == 200, resp.text[:300]

    _seed_targets_with_scans(session_factory, owner_id, count=3)
    queries_with_3 = _count_queries(engine, hit_targets_page)

    _seed_targets_with_scans(session_factory, owner_id, count=17)  # 20 targets total
    queries_with_20 = _count_queries(engine, hit_targets_page)

    assert queries_with_20 == queries_with_3, (
        f"query count scaled with target count ({queries_with_3} -> {queries_with_20} "
        "for 3 -> 20 targets) -- looks like the N+1 on GET /targets regressed"
    )
    # Sanity bound so this test would also fail if some *other* unrelated
    # per-target query were introduced without changing with target count
    # in a way the equality check above wouldn't catch (e.g. a fixed but
    # still-too-high number of queries).
    assert queries_with_20 <= 5, f"expected a small constant number of queries, got {queries_with_20}"
