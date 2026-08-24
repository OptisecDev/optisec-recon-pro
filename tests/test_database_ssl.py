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

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.database import _connect_args_for


def test_postgres_url_requires_ssl():
    assert _connect_args_for("postgresql+asyncpg://user:pass@host/db") == {
        "ssl": "require"
    }


def test_postgres_url_requires_ssl_even_with_sslmode_query_param():
    # The ?sslmode=require query string does nothing for asyncpg on its own --
    # connect_args must supply "ssl" regardless of what the URL string says.
    url = "postgresql+asyncpg://user:pass@host/db?sslmode=require"
    assert _connect_args_for(url) == {"ssl": "require"}


def test_sqlite_url_does_not_get_postgres_ssl_args():
    assert _connect_args_for("sqlite+aiosqlite:///./data/optisec.db") == {}
