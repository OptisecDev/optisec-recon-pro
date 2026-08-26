import os
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

def _ensure_asyncpg_driver(database_url: str) -> str:
    """Force the ``+asyncpg`` driver on any bare postgres(ql):// URL.

    Providers (Neon included) hand out plain ``postgresql://`` connection
    strings with no driver suffix. Passed straight to
    ``create_async_engine()``, SQLAlchemy resolves that to its default sync
    dialect (psycopg2, present here for Alembic) and raises
    ``InvalidRequestError: ... psycopg2 is not async`` at import time --
    before any socket is even opened. This normalization happens purely on
    the URL string and is independent of ``_connect_args_for``, which only
    supplies SSL kwargs for the already-async connection.
    """
    if database_url.startswith("postgresql+asyncpg://") or database_url.startswith("postgres+asyncpg://"):
        return database_url
    if database_url.startswith("postgresql://"):
        return "postgresql+asyncpg://" + database_url[len("postgresql://"):]
    if database_url.startswith("postgres://"):
        return "postgresql+asyncpg://" + database_url[len("postgres://"):]
    return database_url


def _strip_sslmode_query_param(database_url: str) -> str:
    """Drop a stale libpq-style ``?sslmode=`` query param from the URL.

    SQLAlchemy forwards any URL query params it doesn't itself consume
    straight through to the DBAPI's connect() as kwargs -- on top of
    whatever ``connect_args`` the engine was created with. asyncpg's
    connect() has no ``sslmode`` parameter (only ``ssl``, supplied via
    ``_connect_args_for`` below), so a leftover ``?sslmode=require`` in
    DATABASE_URL (the psycopg2/libpq convention some providers hand out)
    reaches asyncpg.connect() as an unexpected kwarg and raises
    ``TypeError: connect() got an unexpected keyword argument 'sslmode'``
    -- even though ``_connect_args_for`` already requests SSL correctly.
    Only postgres URLs carry a DBAPI-forwarded query string, so this is a
    no-op for sqlite.
    """
    if not (database_url.startswith("postgresql") or database_url.startswith("postgres")):
        return database_url
    url = make_url(database_url)
    if "sslmode" not in url.query and "channel_binding" not in url.query:
        return database_url
    return url.difference_update_query(["sslmode", "channel_binding"]).render_as_string(hide_password=False)


DATABASE_URL = _strip_sslmode_query_param(_ensure_asyncpg_driver(os.environ.get(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./data/optisec.db"
)))


def _connect_args_for(database_url: str) -> dict:
    """SSL connect_args for the asyncpg driver.

    SQLAlchemy's asyncpg dialect forwards a URL's query string params
    (e.g. ``?sslmode=require``) verbatim as kwargs to asyncpg.connect(),
    but asyncpg's connect() has no ``sslmode`` parameter (only ``ssl``) --
    so the query string alone never enables SSL and providers like Neon,
    which require SSL, reject the plaintext connection attempt. Request it
    explicitly via connect_args instead.
    """
    if database_url.startswith("postgresql") or database_url.startswith("postgres"):
        # Neon's pooled endpoint runs PgBouncer in transaction mode, which is
        # incompatible with asyncpg's client-side prepared-statement cache
        # (per Neon's docs) -- disable it here.
        return {"ssl": "require", "statement_cache_size": 0}
    return {}


engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    # Explicit, conservative pool sizing: Render runs this app as 2 Uvicorn
    # workers (README.md), each with its own engine/pool, so the default
    # QueuePool sizing (5 + 10 overflow = 15 per worker, 30 total) is more
    # than Neon's pooled endpoint needs and worth capping deliberately.
    pool_size=5,
    max_overflow=5,
    connect_args=_connect_args_for(DATABASE_URL),
)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with SessionLocal() as session:
        yield session


async def init_db():
    from web import models  # noqa: F401 — registers models with Base metadata
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
