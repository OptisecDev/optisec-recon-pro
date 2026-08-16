"""Hybrid storage engine: TimescaleDB (hot, recent) + MinIO/Parquet (cold, archived).

Records younger than ETERNAL_ARCHIVE_AGE_MONTHS live in TimescaleDB (`recon_artifacts`).
`archive_old_records()` moves everything older to a Parquet file per target in MinIO,
deletes it from Postgres, and keeps a small JSON statistical summary alongside the
Parquet object. `query_timeline()` merges both worlds back into one time-ordered view.
"""
import io
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

import pandas as pd
from apscheduler.schedulers.background import BackgroundScheduler
from minio import Minio
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import (
    ETERNAL_ARCHIVE_AGE_MONTHS,
    MINIO_ARCHIVE_BUCKET,
    MINIO_ENDPOINT,
    MINIO_ROOT_PASSWORD,
    MINIO_ROOT_USER,
    MINIO_SECURE,
)
from app.db.session import EternalSessionLocal
from app.models.eternal.recon_artifact import ReconArtifact

logger = logging.getLogger("app.eternal.storage")


def _minio_client() -> Minio:
    return Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ROOT_USER,
        secret_key=MINIO_ROOT_PASSWORD,
        secure=MINIO_SECURE,
    )


def _ensure_bucket(client: Minio) -> None:
    if not client.bucket_exists(MINIO_ARCHIVE_BUCKET):
        client.make_bucket(MINIO_ARCHIVE_BUCKET)


def _archive_object_name(target_id: uuid.UUID) -> str:
    return f"targets/{target_id}/archive.parquet"


def _summary_object_name(target_id: uuid.UUID) -> str:
    return f"targets/{target_id}/archive_summary.json"


async def save_active(record: ReconArtifact, db: AsyncSession) -> ReconArtifact:
    """Persist a recon artifact in TimescaleDB (hot storage) only."""
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record


def archive_old_records(sync_engine=None) -> dict:
    """Move recon_artifacts older than ETERNAL_ARCHIVE_AGE_MONTHS from TimescaleDB
    to Parquet files in MinIO, one archive per target, then delete them from
    TimescaleDB. Returns a run summary. Runs synchronously so it can be called
    both from the weekly BackgroundScheduler job and directly from tests.
    """
    from sqlalchemy import create_engine

    from app.core.config import ETERNAL_DATABASE_URL_SYNC

    engine = sync_engine or create_engine(ETERNAL_DATABASE_URL_SYNC)
    cutoff = datetime.now(timezone.utc) - timedelta(days=30 * ETERNAL_ARCHIVE_AGE_MONTHS)

    with engine.connect() as conn:
        old_rows = pd.read_sql(
            select(ReconArtifact).where(ReconArtifact.created_at < cutoff),
            conn,
        )

    if old_rows.empty:
        return {"archived_targets": 0, "archived_rows": 0, "cutoff": cutoff.isoformat()}

    # Parquet/pyarrow can't serialize raw uuid.UUID or dict objects — flatten to
    # strings/JSON before writing, restored on read in _read_archived_parquet.
    archive_ids = old_rows["id"]
    old_rows = old_rows.copy()
    old_rows["id"] = old_rows["id"].astype(str)
    old_rows["target_id"] = old_rows["target_id"].astype(str)
    old_rows["raw_data"] = old_rows["raw_data"].apply(json.dumps)

    client = _minio_client()
    _ensure_bucket(client)

    for target_id, group in old_rows.groupby("target_id"):
        buf = io.BytesIO()
        group.to_parquet(buf, index=False)
        buf.seek(0)
        object_name = _archive_object_name(target_id)
        client.put_object(
            MINIO_ARCHIVE_BUCKET, object_name, buf, length=buf.getbuffer().nbytes
        )

        summary = {
            "target_id": str(target_id),
            "row_count": int(len(group)),
            "date_range": {
                "from": group["created_at"].min().isoformat(),
                "to": group["created_at"].max().isoformat(),
            },
            "source_types": group["source_type"].value_counts().to_dict(),
            "archived_at": datetime.now(timezone.utc).isoformat(),
        }
        summary_bytes = json.dumps(summary, default=str).encode()
        client.put_object(
            MINIO_ARCHIVE_BUCKET,
            _summary_object_name(target_id),
            io.BytesIO(summary_bytes),
            length=len(summary_bytes),
        )

    archived_ids = list(archive_ids)

    with engine.begin() as conn:
        conn.execute(delete(ReconArtifact).where(ReconArtifact.id.in_(archived_ids)))

    result = {
        "archived_targets": int(old_rows["target_id"].nunique()),
        "archived_rows": len(old_rows),
        "cutoff": cutoff.isoformat(),
    }
    logger.warning("eternal archive run: %s", result)
    return result


def start_archive_scheduler() -> BackgroundScheduler:
    """Runs archive_old_records() once a week."""
    scheduler = BackgroundScheduler()
    scheduler.add_job(archive_old_records, "interval", weeks=1, id="eternal_archive_weekly")
    scheduler.start()
    return scheduler


def _read_archived_parquet(client: Minio, target_id: uuid.UUID) -> pd.DataFrame:
    try:
        response = client.get_object(MINIO_ARCHIVE_BUCKET, _archive_object_name(target_id))
        data = response.read()
        response.close()
        response.release_conn()
        return pd.read_parquet(io.BytesIO(data))
    except Exception:
        return pd.DataFrame()


async def query_timeline(target_id: uuid.UUID, db: AsyncSession) -> list[dict]:
    """Merge recent TimescaleDB rows with archived MinIO/Parquet rows, sorted by time."""
    result = await db.execute(
        select(ReconArtifact).where(ReconArtifact.target_id == target_id)
    )
    active_rows = [
        {
            "id": str(row.id),
            "target_id": str(row.target_id),
            "source_type": row.source_type,
            "raw_data": row.raw_data,
            "created_at": row.created_at.isoformat(),
            "valid_to": row.valid_to.isoformat() if row.valid_to else None,
            "storage": "active",
        }
        for row in result.scalars().all()
    ]

    client = _minio_client()
    archived_df = _read_archived_parquet(client, target_id)
    archived_rows = []
    for _, row in archived_df.iterrows():
        archived_rows.append(
            {
                "id": str(row["id"]),
                "target_id": str(row["target_id"]),
                "source_type": row["source_type"],
                "raw_data": json.loads(row["raw_data"]),
                "created_at": pd.Timestamp(row["created_at"]).isoformat(),
                "valid_to": pd.Timestamp(row["valid_to"]).isoformat()
                if pd.notna(row.get("valid_to"))
                else None,
                "storage": "archived",
            }
        )

    timeline = active_rows + archived_rows
    timeline.sort(key=lambda r: r["created_at"])
    return timeline
