"""Async engine/session for the Eternal Core (TimescaleDB)."""
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import ETERNAL_DATABASE_URL

engine = create_async_engine(ETERNAL_DATABASE_URL, pool_pre_ping=True)
EternalSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_eternal_db():
    async with EternalSessionLocal() as session:
        yield session
