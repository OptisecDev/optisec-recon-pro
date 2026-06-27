"""CVE Submission Pipeline — MITRE CVE Services API + NVD enrichment + local queue."""

import os
import json
import uuid
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional
import httpx

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_SERVICES_BASE = "https://cveawg.mitre.org/api"
QUEUE_FILE = Path("data/cve_queue.json")


def _load_queue() -> list:
    QUEUE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if QUEUE_FILE.exists():
        return json.loads(QUEUE_FILE.read_text())
    return []


def _save_queue(queue: list) -> None:
    QUEUE_FILE.parent.mkdir(parents=True, exist_ok=True)
    QUEUE_FILE.write_text(json.dumps(queue, indent=2, default=str))


async def search_nvd(keyword: str = "", cve_id: str = "", limit: int = 20) -> dict:
    params: dict = {"resultsPerPage": limit, "startIndex": 0}
    if cve_id:
        params["cveId"] = cve_id.upper()
    elif keyword:
        params["keywordSearch"] = keyword
        params["keywordExactMatch"] = False

    api_key = os.environ.get("NVD_API_KEY", "")
    headers = {"apiKey": api_key} if api_key else {}

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.get(NVD_API_BASE, params=params, headers=headers)
            r.raise_for_status()
            data = r.json()
            vulns = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                metrics = cve.get("metrics", {})
                cvss_v3 = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [{}])[0]
                score = cvss_v3.get("cvssData", {}).get("baseScore")
                severity = cvss_v3.get("cvssData", {}).get("baseSeverity")
                desc = next(
                    (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                    "No description",
                )
                vulns.append({
                    "cve_id": cve.get("id"),
                    "description": desc[:300],
                    "severity": severity,
                    "cvss_score": score,
                    "published": cve.get("published"),
                    "modified": cve.get("lastModified"),
                    "references": [r["url"] for r in cve.get("references", [])[:3]],
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
                })
            return {
                "vulnerabilities": vulns,
                "total": data.get("totalResults", len(vulns)),
                "source": "nvd",
            }
        except Exception as e:
            return {"error": str(e), "vulnerabilities": [], "source": "nvd"}


async def draft_cve_report(
    title: str,
    description: str,
    affected_product: str,
    affected_versions: str,
    severity: str,
    cvss_vector: str,
    reporter_name: str,
    reporter_email: str,
    poc_url: str = "",
) -> dict:
    draft_id = f"CVE-DRAFT-{uuid.uuid4().hex[:8].upper()}"
    now = datetime.utcnow().isoformat()

    entry = {
        "draft_id": draft_id,
        "status": "draft",
        "created_at": now,
        "title": title,
        "description": description,
        "affected_product": affected_product,
        "affected_versions": affected_versions,
        "severity": severity,
        "cvss_vector": cvss_vector,
        "reporter_name": reporter_name,
        "reporter_email": reporter_email,
        "poc_url": poc_url,
        "cna_org": os.environ.get("CVE_CNA_ORG", ""),
        "submission_history": [{"timestamp": now, "action": "draft_created"}],
    }

    queue = _load_queue()
    queue.append(entry)
    _save_queue(queue)
    return entry


async def submit_cve_to_mitre(draft_id: str) -> dict:
    queue = _load_queue()
    entry = next((e for e in queue if e["draft_id"] == draft_id), None)
    if not entry:
        return {"error": f"Draft {draft_id} not found"}

    org = os.environ.get("CVE_CNA_ORG", "")
    username = os.environ.get("CVE_CNA_USERNAME", "")
    api_key = os.environ.get("CVE_CNA_API_KEY", "")

    if not all([org, username, api_key]):
        entry["status"] = "pending_credentials"
        entry["submission_history"].append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": "submission_queued",
            "note": "Set CVE_CNA_ORG, CVE_CNA_USERNAME, CVE_CNA_API_KEY to submit",
        })
        _save_queue(queue)
        return {
            "status": "queued",
            "draft_id": draft_id,
            "message": "Report queued. Set CVE CNA credentials to submit.",
        }

    payload = {
        "containers": {
            "cna": {
                "providerMetadata": {"orgId": org, "shortName": org},
                "title": entry["title"],
                "descriptions": [{"lang": "en", "value": entry["description"]}],
                "affected": [{
                    "product": entry["affected_product"],
                    "vendor": "Unknown",
                    "versions": [{"version": entry["affected_versions"], "status": "affected"}],
                }],
                "metrics": [{"cvssV3_1": {"vectorString": entry["cvss_vector"],
                                           "version": "3.1"}}] if entry.get("cvss_vector") else [],
                "references": [{"url": entry["poc_url"]}] if entry.get("poc_url") else [],
            }
        }
    }

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.post(
                f"{CVE_SERVICES_BASE}/cve-id",
                json=payload,
                headers={
                    "CVE-API-ORG": org,
                    "CVE-API-USER": username,
                    "CVE-API-KEY": api_key,
                    "Content-Type": "application/json",
                },
            )
            r.raise_for_status()
            result = r.json()
            cve_id = result.get("cve_id")
            entry["status"] = "submitted"
            entry["cve_id"] = cve_id
            entry["submission_history"].append({
                "timestamp": datetime.utcnow().isoformat(),
                "action": "submitted",
                "cve_id": cve_id,
            })
            _save_queue(queue)
            return {"status": "submitted", "cve_id": cve_id, "draft_id": draft_id}
        except Exception as e:
            entry["status"] = "error"
            entry["submission_history"].append({
                "timestamp": datetime.utcnow().isoformat(),
                "action": "error",
                "error": str(e),
            })
            _save_queue(queue)
            return {"status": "error", "error": str(e), "draft_id": draft_id}


def list_queue() -> list:
    return _load_queue()


def get_draft(draft_id: str) -> Optional[dict]:
    return next((e for e in _load_queue() if e["draft_id"] == draft_id), None)
