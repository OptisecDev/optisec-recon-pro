"""
Unit tests for web/migrate_add_ioc_table.py — the standalone, idempotent
migration that creates the `iocs` table straight from web.models.Ioc
(Ioc.__table__.create()) instead of hand-written SQL.

Runs entirely against a private in-memory SQLite engine created fresh per
test — never touches data/optisec.db or any real database. The migration
module binds `engine` at import time (`from web.database import engine`),
so isolation is done by monkeypatching that already-bound name on the
module itself, not on web.database.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

import web.migrate_add_ioc_table as migrate_module
from web.models import Ioc


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def test_engine(monkeypatch):
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    monkeypatch.setattr(migrate_module, "engine", engine)
    yield engine
    _run(engine.dispose())


def _inspect(engine, fn):
    async def _go():
        async with engine.begin() as conn:
            return await conn.run_sync(lambda sync_conn: fn(inspect(sync_conn)))
    return _run(_go())


def _table_names(engine):
    return _inspect(engine, lambda insp: insp.get_table_names())


def _columns(engine, table_name):
    return _inspect(engine, lambda insp: insp.get_columns(table_name))


def _unique_constraints(engine, table_name):
    return _inspect(engine, lambda insp: insp.get_unique_constraints(table_name))


def _indexes(engine, table_name):
    return _inspect(engine, lambda insp: insp.get_indexes(table_name))


def test_creates_table_when_missing(test_engine):
    assert "iocs" not in _table_names(test_engine)
    _run(migrate_module.migrate())
    assert "iocs" in _table_names(test_engine)


def test_idempotent_running_twice_does_not_error(test_engine):
    _run(migrate_module.migrate())
    _run(migrate_module.migrate())  # must not raise, must not touch schema
    assert "iocs" in _table_names(test_engine)


def test_second_run_prints_already_exists_and_skips(test_engine, capsys):
    _run(migrate_module.migrate())
    capsys.readouterr()
    _run(migrate_module.migrate())
    out = capsys.readouterr().out
    assert "iocs" in out
    assert "موجود مسبقاً" in out


def test_created_columns_match_ioc_model(test_engine):
    _run(migrate_module.migrate())
    actual_cols = {c["name"]: c for c in _columns(test_engine, "iocs")}
    expected_cols = {c.name: c for c in Ioc.__table__.columns}

    assert set(actual_cols) == set(expected_cols)
    for name, expected_col in expected_cols.items():
        assert actual_cols[name]["nullable"] == expected_col.nullable, name


def test_created_unique_constraint_matches_model(test_engine):
    _run(migrate_module.migrate())
    unique_sets = {tuple(sorted(uc["column_names"])) for uc in _unique_constraints(test_engine, "iocs")}
    assert ("ioc_type", "ioc_value") in unique_sets


def test_created_indexes_include_model_indexes(test_engine):
    _run(migrate_module.migrate())
    actual_index_cols = {tuple(sorted(ix["column_names"])) for ix in _indexes(test_engine, "iocs")}
    expected_index_cols = {tuple(sorted(ix.columns.keys())) for ix in Ioc.__table__.indexes}
    assert expected_index_cols.issubset(actual_index_cols)


def test_never_issues_drop_or_alter(test_engine):
    """Guard against regressions: the migration must only ever create the
    table, never drop or alter anything — even when run repeatedly."""
    _run(migrate_module.migrate())
    _run(migrate_module.migrate())

    with open(migrate_module.__file__, encoding="utf-8") as f:
        source = f.read()
    assert "DROP TABLE" not in source.upper()
    assert "ALTER TABLE" not in source.upper()
