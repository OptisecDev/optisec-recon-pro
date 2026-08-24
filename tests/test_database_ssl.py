"""
Regression test for the Neon Postgres startup failure:

    asyncpg.exceptions.InvalidAuthorizationSpecificationError: SSL/TLS required

SQLAlchemy's asyncpg dialect forwards a DATABASE_URL's query string params
(e.g. ``?sslmode=require``) verbatim as kwargs to asyncpg.connect(), but
asyncpg.connect() has no ``sslmode`` keyword (only ``ssl``) -- so the query
string alone never actually requests SSL, and providers that require it
(Neon) reject the plaintext connection attempt. web/database.py must
request SSL explicitly via connect_args instead of relying on the URL.
"""

import asyncio
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.database import _connect_args_for, asyncpg_connect_ipv4, ipv4_only_resolution


def test_postgres_url_requires_ssl():
    args = _connect_args_for("postgresql+asyncpg://user:pass@host/db")
    assert args["ssl"] == "require"
    assert args["async_creator_fn"] is asyncpg_connect_ipv4


def test_postgres_url_requires_ssl_even_with_sslmode_query_param():
    # The ?sslmode=require query string does nothing for asyncpg on its own --
    # connect_args must supply "ssl" regardless of what the URL string says.
    url = "postgresql+asyncpg://user:pass@host/db?sslmode=require"
    args = _connect_args_for(url)
    assert args["ssl"] == "require"
    assert args["async_creator_fn"] is asyncpg_connect_ipv4


def test_sqlite_url_does_not_get_postgres_ssl_args():
    assert _connect_args_for("sqlite+aiosqlite:///./data/optisec.db") == {}


def test_ipv4_only_resolution_forces_af_inet_and_restores_after():
    # Regression test for the Render->Neon ConnectionDoesNotExistError:
    # Render's outbound networking sometimes prefers an IPv6 route to Neon
    # that fails/hangs mid-handshake. ipv4_only_resolution() must force
    # every getaddrinfo() call made through it to family=AF_INET, and must
    # restore the original loop.getaddrinfo afterwards.
    async def run():
        loop = asyncio.get_running_loop()
        original = loop.getaddrinfo
        seen_family = None

        async def fake_getaddrinfo(host, port, *, family=0, type=0, proto=0, flags=0):
            nonlocal seen_family
            seen_family = family
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port))]

        loop.getaddrinfo = fake_getaddrinfo
        try:
            async with ipv4_only_resolution():
                # Request AF_UNSPEC (0) as create_connection would by default;
                # the context manager must upgrade it to AF_INET regardless.
                await loop.getaddrinfo("example-neon-host.example.com", 5432, family=0)
            assert seen_family == socket.AF_INET
            assert loop.getaddrinfo is fake_getaddrinfo
        finally:
            loop.getaddrinfo = original

    asyncio.run(run())
