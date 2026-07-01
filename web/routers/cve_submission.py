"""
CVE Submission Pipeline router — turns a scan finding (or a manually entered
vulnerability) into a locally-stored CVE report draft, following MITRE CNA
conventions, exportable as a CVE JSON 5.0 record.

SAFETY NOTICE — read before wiring a "submit" button to anything:
This router never submits, reserves, or publishes a CVE with MITRE or any
CNA. There is no outbound call to cveawg.mitre.org anywhere in this codebase.
Every endpoint here only reads/writes the local `cve_drafts` table or, for
/search, performs a read-only lookup against the public NVD API to help spot
duplicates. Turning a draft into a real, numbered CVE is an out-of-band,
human action performed by someone with an approved CNA account — see the
disclaimer returned on every draft response.

Persistence/query logic lives in plain functions (create_draft, list_drafts,
get_draft) rather than inline in the endpoint bodies, mirroring
web/routers/threat_sharing.py and web/routers/honeypot.py, so tests can call
them directly against an isolated DB session.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Request, Depends, HTTPException, Response
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from web.database import get_db
from web.models import User, Finding, Scan, CveDraft
from web.auth import get_current_user
from modules.bug_bounty import cve_pipeline

router = APIRouter(prefix="/api/cve", tags=["cve-pipeline"])

DISCLAIMER_EN = (
    "This is a drafting assistant only. Actual submission to MITRE requires "
    "human review and an approved CNA account."
)
DISCLAIMER_AR = (
    "هذه أداة مساعدة لصياغة التقرير فقط — التقديم الفعلي لـ MITRE يتطلب "
    "مراجعة بشرية وحساب CNA معتمد."
)


async def _user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    return await get_current_user(request, db)


def _draft_to_dict(row: CveDraft) -> dict:
    return {
        "id": row.id,
        "draft_ref": row.draft_ref,
        "status": row.status,
        "source_module": row.source_module,
        "finding_id": row.finding_id,
        "title": row.title,
        "description": row.description,
        "vendor": row.vendor,
        "product": row.product,
        "versions_affected": row.versions_affected,
        "problem_type": row.problem_type,
        "severity": row.severity,
        "cvss_vector": row.cvss_vector,
        "cvss_score": row.cvss_score,
        "references": row.references,
        "credits": row.credits,
        "reporter_name": row.reporter_name,
        "reporter_email": row.reporter_email,
        "cna_org": row.cna_org,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "exported_at": row.exported_at.isoformat() if row.exported_at else None,
        "disclaimer_en": DISCLAIMER_EN,
        "disclaimer_ar": DISCLAIMER_AR,
    }


def _list_item(row: CveDraft) -> dict:
    return {
        "id": row.id,
        "draft_ref": row.draft_ref,
        "status": row.status,
        "title": row.title,
        "severity": row.severity,
        "product": row.product,
        "source_module": row.source_module,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


# ── Persistence (DB logic, unit-testable directly) ─────────────────────────

async def get_finding_for_user(db: AsyncSession, finding_id: int, user_id: int) -> Optional[Finding]:
    stmt = (
        select(Finding).join(Scan)
        .where(Finding.id == finding_id, Scan.user_id == user_id)
    )
    return (await db.execute(stmt)).scalars().first()


async def create_draft(db: AsyncSession, *, user: User, payload: dict, finding: Optional[Finding]) -> CveDraft:
    base: dict = {}
    source_module = "manual"
    if finding is not None:
        source_module = "scan_finding"
        base = cve_pipeline.draft_from_finding({
            "type": finding.vuln_type, "severity": finding.severity,
            "url": finding.url, "parameter": finding.parameter,
            "payload": finding.payload, "evidence": finding.evidence,
        })

    merged = dict(base)
    for key in (
        "title", "description", "vendor", "product", "versions_affected",
        "problem_type", "severity", "cvss_vector", "cvss_score",
        "references", "credits", "cna_org",
    ):
        value = payload.get(key)
        if value not in (None, ""):
            merged[key] = value

    if not merged.get("title") or not merged.get("description"):
        raise ValueError("title and description are required (either supply them or derive from finding_id)")

    row = CveDraft(
        draft_ref=cve_pipeline.new_draft_ref(),
        user_id=user.id,
        finding_id=finding.id if finding is not None else None,
        source_module=source_module,
        status="draft",
        title=merged.get("title", ""),
        description=merged.get("description", ""),
        vendor=merged.get("vendor", "Unknown"),
        product=merged.get("product"),
        versions_affected=merged.get("versions_affected"),
        problem_type=merged.get("problem_type"),
        severity=merged.get("severity", "medium"),
        cvss_vector=merged.get("cvss_vector"),
        cvss_score=merged.get("cvss_score"),
        references=merged.get("references") or [],
        credits=merged.get("credits") or [],
        reporter_name=payload.get("reporter_name") or user.username,
        reporter_email=payload.get("reporter_email") or user.email,
        cna_org=merged.get("cna_org"),
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


async def list_drafts(db: AsyncSession, *, user_id: int, status: Optional[str] = None, limit: int = 100) -> list[CveDraft]:
    stmt = select(CveDraft).where(CveDraft.user_id == user_id)
    if status:
        stmt = stmt.where(CveDraft.status == status)
    stmt = stmt.order_by(CveDraft.created_at.desc()).limit(min(limit, 200))
    return list((await db.execute(stmt)).scalars().all())


async def get_draft(db: AsyncSession, *, draft_id: int, user_id: int) -> Optional[CveDraft]:
    stmt = select(CveDraft).where(CveDraft.id == draft_id, CveDraft.user_id == user_id)
    return (await db.execute(stmt)).scalars().first()


# ── Endpoints ───────────────────────────────────────────────────────────────

@router.get(
    "/search",
    summary="Search NVD for existing CVEs",
    description="Read-only lookup against the public NVD API — use it to check for an existing/duplicate CVE before drafting a new one. Never sends anything.",
)
async def cve_search(keyword: str = "", cve_id: str = "", user: User = Depends(_user)):
    return await cve_pipeline.search_nvd(keyword=keyword, cve_id=cve_id)


@router.post(
    "/draft",
    summary="Generate a CVE report draft",
    description=(
        "Creates a locally-stored CVE draft. Pass finding_id to auto-populate "
        "from an existing scan finding (GET /api/findings), optionally overriding "
        "any field; or supply title/description/etc. manually. "
        + DISCLAIMER_EN
    ),
)
async def cve_draft(request: Request, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    data = await request.json()
    finding = None
    finding_id = data.get("finding_id")
    if finding_id is not None:
        finding = await get_finding_for_user(db, int(finding_id), user.id)
        if finding is None:
            raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    try:
        row = await create_draft(db, user=user, payload=data, finding=finding)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return JSONResponse(_draft_to_dict(row))


@router.get(
    "/drafts",
    summary="List CVE drafts",
    description="Lists this user's CVE drafts, newest first. Filter by status (draft | exported).",
)
async def cve_drafts(status: Optional[str] = None, limit: int = 100,
                      user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    rows = await list_drafts(db, user_id=user.id, status=status, limit=limit)
    return JSONResponse({"drafts": [_list_item(r) for r in rows], "count": len(rows)})


@router.get(
    "/drafts/{draft_id}",
    summary="Get a single CVE draft",
)
async def cve_draft_detail(draft_id: int, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    row = await get_draft(db, draft_id=draft_id, user_id=user.id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Draft {draft_id} not found")
    return JSONResponse(_draft_to_dict(row))


@router.get(
    "/drafts/{draft_id}/export",
    summary="Export a CVE draft as a CVE JSON 5.0 record",
    description=(
        "Downloads the draft rendered as a CVE JSON 5.0 CVE Record. "
        "cveId/assignerOrgId are TBD placeholders — no real CVE ID exists until "
        "a CNA actually assigns one, which this tool does not do. " + DISCLAIMER_EN
    ),
)
async def cve_draft_export(draft_id: int, user: User = Depends(_user), db: AsyncSession = Depends(get_db)):
    row = await get_draft(db, draft_id=draft_id, user_id=user.id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Draft {draft_id} not found")

    record = cve_pipeline.build_cve_json_5(_draft_to_dict(row))

    row.status = "exported"
    row.exported_at = datetime.utcnow()
    await db.commit()

    import json
    body = json.dumps(record, indent=2, ensure_ascii=False)
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{row.draft_ref}.cve.json"'},
    )
