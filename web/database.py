import os
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


DATABASE_URL = _ensure_asyncpg_driver(os.environ.get(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./data/optisec.db"
))


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
        return {"ssl": "require"}
    return {}


engine = create_async_engine(
    DATABASE_URL, echo=False, pool_pre_ping=True, connect_args=_connect_args_for(DATABASE_URL)
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
