import asyncio
import contextlib
import os
import socket
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./data/optisec.db"
)

# Fail fast rather than hang if Render's route to Neon is broken.
DB_CONNECT_TIMEOUT = 10


@contextlib.asynccontextmanager
async def ipv4_only_resolution():
    """Constrain DNS resolution on the running loop to IPv4 (AF_INET) only.

    Render's outbound networking sometimes prefers an IPv6 route to Neon
    that fails or hangs mid-handshake (asyncpg.ConnectionDoesNotExistError),
    while IPv4 clients (e.g. Neon's own SQL Editor) connect fine.

    We deliberately do NOT pre-resolve the hostname to an IP and pass that
    IP as asyncpg's ``host=`` -- asyncpg has no libpq-style ``hostaddr``
    parameter to dial a specific address while keeping the original
    hostname for TLS SNI. It hardcodes ``server_hostname`` to whatever
    string was used to dial the socket (see
    asyncpg/connect_utils.py:_create_ssl_connection, ~line 986/1006), and
    Neon's proxy routes connections by SNI hostname. Substituting a raw IP
    for ``host`` would send the IP as SNI and break Neon's routing.

    Instead, only the address family chosen during DNS resolution is
    constrained here; the hostname string asyncpg receives (and uses for
    SNI) is untouched, so this forces IPv4 without breaking Neon routing
    or certificate verification.
    """
    loop = asyncio.get_running_loop()
    original_getaddrinfo = loop.getaddrinfo

    async def _getaddrinfo_ipv4(host, port, *, family=0, type=0, proto=0, flags=0):
        return await original_getaddrinfo(
            host, port, family=socket.AF_INET, type=type, proto=proto, flags=flags
        )

    loop.getaddrinfo = _getaddrinfo_ipv4
    try:
        yield
    finally:
        loop.getaddrinfo = original_getaddrinfo


async def asyncpg_connect_ipv4(*args, **kwargs):
    """asyncpg connection creator that forces IPv4 DNS resolution.

    Wired in as SQLAlchemy's ``async_creator_fn`` so the pooled engine
    connects the same way as the raw asyncpg debug probe.
    """
    import asyncpg

    kwargs.setdefault("timeout", DB_CONNECT_TIMEOUT)
    async with ipv4_only_resolution():
        return await asyncpg.connect(*args, **kwargs)


def _connect_args_for(database_url: str) -> dict:
    """Connect_args for the asyncpg driver: SSL + forced IPv4 resolution.

    SQLAlchemy's asyncpg dialect forwards a URL's query string params
    (e.g. ``?sslmode=require``) verbatim as kwargs to asyncpg.connect(),
    but asyncpg's connect() has no ``sslmode`` parameter (only ``ssl``) --
    so the query string alone never enables SSL and providers like Neon,
    which require SSL, reject the plaintext connection attempt. Request it
    explicitly via connect_args instead.

    ``async_creator_fn`` routes the actual connect through
    ``asyncpg_connect_ipv4`` above, which forces IPv4 resolution (see its
    docstring for why the host string itself must stay the original
    hostname, not a pre-resolved IP).
    """
    if database_url.startswith("postgresql") or database_url.startswith("postgres"):
        return {"ssl": "require", "async_creator_fn": asyncpg_connect_ipv4}
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
