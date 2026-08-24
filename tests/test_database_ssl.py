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

from web.database import _connect_args_for, _ensure_asyncpg_driver, _strip_sslmode_query_param


def test_bare_postgresql_url_gets_asyncpg_driver():
    # Regression test: providers (Neon included) hand out plain
    # "postgresql://" URLs with no driver suffix. Passed straight to
    # create_async_engine(), SQLAlchemy resolves that to its default sync
    # dialect (psycopg2) and raises InvalidRequestError at import time,
    # before any connection is attempted. DATABASE_URL must always be
    # normalized to the asyncpg driver.
    assert _ensure_asyncpg_driver("postgresql://user:pass@host/db") == (
        "postgresql+asyncpg://user:pass@host/db"
    )


def test_legacy_postgres_scheme_url_gets_asyncpg_driver():
    assert _ensure_asyncpg_driver("postgres://user:pass@host/db") == (
        "postgresql+asyncpg://user:pass@host/db"
    )


def test_url_already_using_asyncpg_driver_is_left_untouched():
    url = "postgresql+asyncpg://user:pass@host/db"
    assert _ensure_asyncpg_driver(url) == url


def test_non_postgres_url_is_left_untouched():
    url = "sqlite+aiosqlite:///./data/optisec.db"
    assert _ensure_asyncpg_driver(url) == url


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


def test_stale_sslmode_query_param_is_stripped_from_postgres_url():
    # Regression test: TypeError: connect() got an unexpected keyword
    # argument 'sslmode' -- SQLAlchemy forwards any URL query params it
    # doesn't consume straight to asyncpg.connect() as kwargs, on top of
    # connect_args. A leftover "?sslmode=require" (the psycopg2/libpq
    # convention) must be dropped from DATABASE_URL itself, since
    # connect_args alone can't stop SQLAlchemy from also forwarding it.
    url = "postgresql+asyncpg://user:pass@host/db?sslmode=require"
    assert _strip_sslmode_query_param(url) == "postgresql+asyncpg://user:pass@host/db"


def test_sslmode_alongside_other_query_params_only_drops_sslmode():
    url = "postgresql+asyncpg://user:pass@host/db?sslmode=require&application_name=optisec"
    assert _strip_sslmode_query_param(url) == (
        "postgresql+asyncpg://user:pass@host/db?application_name=optisec"
    )


def test_url_without_sslmode_is_left_untouched():
    url = "postgresql+asyncpg://user:pass@host/db"
    assert _strip_sslmode_query_param(url) == url


def test_sqlite_url_is_left_untouched_by_sslmode_strip():
    url = "sqlite+aiosqlite:///./data/optisec.db"
    assert _strip_sslmode_query_param(url) == url
