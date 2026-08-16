"""Unit test for the Eternal Core archival job: 100 old recon_artifacts rows
should be flattened to Parquet, uploaded to MinIO, and deleted from Postgres.
Uses fakes for the SQL engine and MinIO client — no live infra required.
"""
import io
import json
import uuid
from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest

from app.services.storage import hybrid_repository


class _FakeConn:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, stmt):
        self.last_statement = stmt


class _FakeEngine:
    def __init__(self):
        self.begin_conn = None

    def connect(self):
        return _FakeConn()

    def begin(self):
        self.begin_conn = _FakeConn()
        return self.begin_conn


class _FakeMinioClient:
    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def bucket_exists(self, bucket):
        return True

    def make_bucket(self, bucket):
        pass

    def put_object(self, bucket, object_name, data, length):
        self.objects[object_name] = data.read()


def _build_old_rows(n: int, target_ids: list[uuid.UUID]) -> pd.DataFrame:
    old_created_at = datetime.now(timezone.utc) - timedelta(days=200)
    rows = []
    for i in range(n):
        rows.append(
            {
                "id": uuid.uuid4(),
                "target_id": target_ids[i % len(target_ids)],
                "source_type": "mock_engine:email",
                "raw_data": {"breaches": [{"source": "LinkedIn", "year": 2022}], "n": i},
                "created_at": old_created_at,
                "updated_at": old_created_at,
                "valid_to": None,
            }
        )
    return pd.DataFrame(rows)


def test_archive_old_records_moves_100_rows_to_parquet(monkeypatch):
    target_ids = [uuid.uuid4(), uuid.uuid4(), uuid.uuid4()]
    old_rows = _build_old_rows(100, target_ids)

    monkeypatch.setattr(hybrid_repository.pd, "read_sql", lambda *a, **k: old_rows)

    fake_client = _FakeMinioClient()
    monkeypatch.setattr(hybrid_repository, "_minio_client", lambda: fake_client)

    fake_engine = _FakeEngine()
    result = hybrid_repository.archive_old_records(sync_engine=fake_engine)

    assert result["archived_rows"] == 100
    assert result["archived_targets"] == 3

    # One parquet + one summary object per target
    parquet_objects = [k for k in fake_client.objects if k.endswith("archive.parquet")]
    summary_objects = [k for k in fake_client.objects if k.endswith("archive_summary.json")]
    assert len(parquet_objects) == 3
    assert len(summary_objects) == 3

    total_archived_rows = 0
    for key in parquet_objects:
        df = pd.read_parquet(io.BytesIO(fake_client.objects[key]))
        total_archived_rows += len(df)
        # raw_data must round-trip as JSON, not a raw dict, for parquet compatibility
        assert isinstance(df.iloc[0]["raw_data"], str)
        json.loads(df.iloc[0]["raw_data"])
    assert total_archived_rows == 100

    for key in summary_objects:
        summary = json.loads(fake_client.objects[key])
        assert summary["row_count"] > 0
        assert "date_range" in summary

    # DELETE was issued against TimescaleDB for the archived ids
    assert fake_engine.begin_conn is not None
    assert fake_engine.begin_conn.last_statement is not None


def test_archive_old_records_noop_when_nothing_old(monkeypatch):
    monkeypatch.setattr(hybrid_repository.pd, "read_sql", lambda *a, **k: pd.DataFrame())
    result = hybrid_repository.archive_old_records(sync_engine=_FakeEngine())
    assert result["archived_rows"] == 0
    assert result["archived_targets"] == 0
