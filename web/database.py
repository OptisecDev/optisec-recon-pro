import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./data/optisec.db"
)


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
    DATABASE_URL, echo=False, connect_args=_connect_args_for(DATABASE_URL)
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
