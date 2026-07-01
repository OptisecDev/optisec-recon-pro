"""CVE Submission Pipeline — drafting aid only.

Workflow: a scan finding (or a manually-entered vulnerability) is turned into
a CVE report draft that follows MITRE CNA conventions (title, description,
affected product/versions, CWE problem type, CVSS, references, credits),
persisted locally (web.models.CveDraft), and made available for export as a
CVE JSON 5.0 record.

IMPORTANT — this module never talks to MITRE or any CNA system. There is
intentionally no "submit" function here: assigning/publishing a real CVE ID
requires an approved CNA account and a human decision, both outside the
scope of this tool. The only outbound network call in this module is the
read-only NVD lookup (search_nvd), used to check for existing/duplicate
CVEs — nothing here ever pushes data out.
"""
from __future__ import annotations

import os
import re
import uuid
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

import httpx

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CVE_JSON_DATA_VERSION = "5.1"

# ─── CWE mapping (best-effort — reviewer should confirm before real submission) ──

CWE_BY_VULN_TYPE: dict[str, dict[str, str]] = {
    "xss":                {"cwe_id": "CWE-79",  "label": "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)"},
    "sqli":               {"cwe_id": "CWE-89",  "label": "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)"},
    "ssrf":                {"cwe_id": "CWE-918", "label": "Server-Side Request Forgery (SSRF)"},
    "lfi":                {"cwe_id": "CWE-98",  "label": "Improper Control of Filename for Include/Require Statement in PHP Program (File Inclusion)"},
    "rfi":                {"cwe_id": "CWE-98",  "label": "Improper Control of Filename for Include/Require Statement in PHP Program (File Inclusion)"},
    "path traversal":     {"cwe_id": "CWE-22",  "label": "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)"},
    "open redirect":      {"cwe_id": "CWE-601", "label": "URL Redirection to Untrusted Site (Open Redirect)"},
    "csrf":               {"cwe_id": "CWE-352", "label": "Cross-Site Request Forgery (CSRF)"},
    "rce":                {"cwe_id": "CWE-94",  "label": "Improper Control of Generation of Code (Code Injection)"},
    "command injection":  {"cwe_id": "CWE-78",  "label": "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)"},
    "idor":               {"cwe_id": "CWE-639", "label": "Authorization Bypass Through User-Controlled Key (IDOR)"},
    "xxe":                {"cwe_id": "CWE-611", "label": "Improper Restriction of XML External Entity Reference (XXE)"},
    "insecure deserialization": {"cwe_id": "CWE-502", "label": "Deserialization of Untrusted Data"},
    "broken auth":        {"cwe_id": "CWE-287", "label": "Improper Authentication"},
    "information disclosure": {"cwe_id": "CWE-200", "label": "Exposure of Sensitive Information to an Unauthorized Actor"},
}

_DEFAULT_CWE = {"cwe_id": "NVD-CWE-noinfo", "label": "Insufficient information to classify (reviewer should assign a CWE)"}

# ─── Suggested CVSS 3.1 starting points per severity (editable, not authoritative) ──

SUGGESTED_CVSS_BY_SEVERITY: dict[str, dict[str, str]] = {
    "critical": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": "9.8"},
    "high":     {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", "score": "8.1"},
    "medium":   {"vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N", "score": "5.4"},
    "low":      {"vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", "score": "2.4"},
}


def cwe_for_vuln_type(vuln_type: str) -> dict[str, str]:
    key = (vuln_type or "").strip().lower()
    return CWE_BY_VULN_TYPE.get(key, _DEFAULT_CWE)


def suggested_cvss(severity: str) -> dict[str, str]:
    key = (severity or "").strip().lower()
    return SUGGESTED_CVSS_BY_SEVERITY.get(key, SUGGESTED_CVSS_BY_SEVERITY["medium"])


def new_draft_ref() -> str:
    return f"CVE-DRAFT-{uuid.uuid4().hex[:8].upper()}"


def _product_from_url(url: str) -> str:
    if not url:
        return "Unknown"
    try:
        netloc = urlparse(url).netloc or url
        return netloc.split(":")[0] or "Unknown"
    except Exception:
        return "Unknown"


def draft_from_finding(finding: dict) -> dict:
    """Build suggested draft fields from a scan Finding row (as returned by
    GET /api/findings: id, scan_id, type, severity, url, parameter, payload,
    evidence). Every field here is a starting point — the human reviewer is
    expected to refine title/description/versions before export."""
    vuln_type = finding.get("type") or finding.get("vuln_type") or "Unknown"
    severity = (finding.get("severity") or "medium").lower()
    url = finding.get("url") or ""
    parameter = finding.get("parameter") or ""
    evidence = finding.get("evidence") or ""
    payload = finding.get("payload") or ""
    product = _product_from_url(url)
    cwe = cwe_for_vuln_type(vuln_type)
    cvss = suggested_cvss(severity)

    description_parts = [f"A {vuln_type} vulnerability was identified in {product}."]
    if parameter:
        description_parts.append(f"The issue affects the '{parameter}' parameter.")
    if evidence:
        description_parts.append(f"Evidence: {evidence}")
    elif payload:
        description_parts.append(f"Proof-of-concept payload used during testing: {payload}")

    return {
        "title": f"{vuln_type} vulnerability in {product}",
        "description": " ".join(description_parts),
        "vendor": "Unknown",
        "product": product,
        "versions_affected": [{"version": "unspecified", "status": "affected"}],
        "problem_type": f"{cwe['cwe_id']} {cwe['label']}",
        "severity": severity,
        "cvss_vector": cvss["vector"],
        "cvss_score": cvss["score"],
        "references": [url] if url else [],
    }


def build_cve_json_5(draft: dict) -> dict:
    """Render a draft (as a dict of CveDraft fields) as a CVE JSON 5.0
    CVE Record. `cveId`/`assignerOrgId` are left as TBD placeholders since no
    real CVE ID has been reserved — a CNA assigns those at actual submission
    time, which this tool does not perform."""
    references = draft.get("references") or []
    credits = draft.get("credits") or []
    versions = draft.get("versions_affected") or [{"version": "unspecified", "status": "affected"}]

    problem_type = draft.get("problem_type") or ""
    cwe_id = problem_type.split(" ", 1)[0] if problem_type.startswith("CWE-") else None

    metrics = []
    if draft.get("cvss_vector"):
        metrics.append({
            "format": "CVSS",
            "cvssV3_1": {
                "version": "3.1",
                "vectorString": draft["cvss_vector"],
                "baseScore": float(draft["cvss_score"]) if draft.get("cvss_score") else None,
                "baseSeverity": (draft.get("severity") or "").upper() or None,
            },
        })

    cna_container = {
        "providerMetadata": {
            "orgId": draft.get("cna_org") or "TBD",
            "shortName": draft.get("cna_org") or "TBD",
        },
        "title": draft.get("title", ""),
        "descriptions": [{"lang": "en", "value": draft.get("description", "")}],
        "affected": [{
            "vendor": draft.get("vendor") or "Unknown",
            "product": draft.get("product") or "Unknown",
            "versions": versions,
        }],
        "problemTypes": [{
            "descriptions": [{
                "lang": "en",
                "description": problem_type or "Unclassified",
                "type": "CWE",
                **({"cweId": cwe_id} if cwe_id else {}),
            }]
        }],
        "references": [{"url": r} for r in references],
        "metrics": metrics,
        "credits": [
            {"lang": "en", "value": c.get("name", ""), "type": c.get("type", "finder")}
            for c in credits
        ],
        "source": {"discovery": "INTERNAL"},
    }

    return {
        "dataType": "CVE_RECORD",
        "dataVersion": CVE_JSON_DATA_VERSION,
        "cveMetadata": {
            "cveId": "CVE-TBD-TBD",
            "assignerOrgId": "TBD",
            "assignerShortName": draft.get("cna_org") or "TBD",
            "state": "DRAFT",
        },
        "containers": {"cna": cna_container},
    }


async def search_nvd(keyword: str = "", cve_id: str = "", limit: int = 20) -> dict:
    """Read-only lookup against the public NVD API — used to check for
    existing/duplicate CVEs before drafting a new one. Never sends anything."""
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
                    "references": [ref["url"] for ref in cve.get("references", [])[:3]],
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
                })
            return {
                "vulnerabilities": vulns,
                "total": data.get("totalResults", len(vulns)),
                "source": "nvd",
            }
        except Exception as e:
            return {"error": str(e), "vulnerabilities": [], "source": "nvd"}
