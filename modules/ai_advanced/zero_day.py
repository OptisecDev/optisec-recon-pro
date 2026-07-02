"""Zero-Day Prediction Engine — AI-driven vulnerability forecasting."""

import os
import json
import asyncio
import httpx
from datetime import datetime
from pathlib import Path
from typing import Optional

from config import GROQ_MODEL

PREDICTIONS_FILE = Path("data/zero_day_predictions.json")


def _load_predictions() -> list:
    PREDICTIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
    if PREDICTIONS_FILE.exists():
        return json.loads(PREDICTIONS_FILE.read_text())
    return []


def _save_predictions(preds: list) -> None:
    PREDICTIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
    PREDICTIONS_FILE.write_text(json.dumps(preds, indent=2, default=str))


# Risk indicators derived from research on zero-day patterns
ZERO_DAY_INDICATORS = {
    "memory_corruption_patterns": [
        "use-after-free", "heap overflow", "stack overflow", "double-free",
        "buffer overflow", "integer overflow", "out-of-bounds", "type confusion",
        "race condition", "uninitialized memory",
    ],
    "high_value_targets": [
        "browser", "pdf reader", "office suite", "vpn", "firewall", "router",
        "active directory", "exchange", "sharepoint", "sap", "oracle",
    ],
    "exploitation_primitives": [
        "arbitrary code execution", "privilege escalation", "sandbox escape",
        "kernel exploit", "jit compiler", "jit spray",
    ],
    "disclosure_patterns": [
        "partial patch", "incomplete fix", "bypass", "variant",
        "patch gap", "n-day",
    ],
}

EXPLOIT_DB_BASE = "https://www.exploit-db.com/search"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def predict_zero_days(target_software: str, version: str = "") -> dict:
    """Predict zero-day risk for given software using threat intel + heuristics."""
    groq_key = os.environ.get("GROQ_API_KEY", "")

    # Fetch known vulnerabilities context
    nvd_data = await _fetch_nvd_context(target_software, version)
    kev_data = await _fetch_cisa_kev(target_software)

    if groq_key:
        ai_analysis = await _ai_zero_day_analysis(
            target_software, version, nvd_data, kev_data, groq_key
        )
    else:
        ai_analysis = _heuristic_analysis(target_software, nvd_data, kev_data)

    prediction = {
        "target_software": target_software,
        "version": version,
        "analyzed_at": datetime.utcnow().isoformat(),
        "risk_score": ai_analysis.get("risk_score", 0.0),
        "risk_level": ai_analysis.get("risk_level", "unknown"),
        "predicted_vulnerability_classes": ai_analysis.get("vulnerability_classes", []),
        "threat_actors_likely": ai_analysis.get("threat_actors", []),
        "time_to_exploit_estimate": ai_analysis.get("tte_days"),
        "indicators": ai_analysis.get("indicators", []),
        "recommendations": ai_analysis.get("recommendations", []),
        "known_cves": nvd_data.get("recent_cves", [])[:5],
        "in_cisa_kev": kev_data.get("found", False),
        "kev_entries": kev_data.get("entries", [])[:3],
        "confidence": ai_analysis.get("confidence", 0.0),
        "source": "groq_ai" if groq_key else "heuristic",
    }

    preds = _load_predictions()
    preds.insert(0, prediction)
    _save_predictions(preds[:100])

    return prediction


async def _fetch_nvd_context(software: str, version: str) -> dict:
    async with httpx.AsyncClient(timeout=20) as client:
        try:
            params = {
                "keywordSearch": f"{software} {version}".strip(),
                "resultsPerPage": 10,
                "startIndex": 0,
            }
            api_key = os.environ.get("NVD_API_KEY", "")
            headers = {"apiKey": api_key} if api_key else {}
            r = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params,
                headers=headers,
            )
            r.raise_for_status()
            data = r.json()
            cves = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                metrics = cve.get("metrics", {})
                cvss_list = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
                score = cvss_list[0].get("cvssData", {}).get("baseScore") if cvss_list else None
                desc = next(
                    (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                    ""
                )
                cves.append({
                    "id": cve.get("id"),
                    "score": score,
                    "description": desc[:200],
                    "published": cve.get("published"),
                })
            return {"recent_cves": cves, "total": data.get("totalResults", 0)}
        except Exception as e:
            return {"recent_cves": [], "total": 0, "error": str(e)}


async def _fetch_cisa_kev(software: str) -> dict:
    async with httpx.AsyncClient(timeout=20) as client:
        try:
            r = await client.get(CISA_KEV_URL)
            r.raise_for_status()
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            keyword = software.lower()
            matches = [
                {
                    "cve_id": v.get("cveID"),
                    "product": v.get("product"),
                    "vendor": v.get("vendorProject"),
                    "date_added": v.get("dateAdded"),
                    "required_action": v.get("requiredAction"),
                }
                for v in vulns
                if keyword in (v.get("product", "") + v.get("vendorProject", "")).lower()
            ]
            return {"found": len(matches) > 0, "entries": matches[:5], "total": len(matches)}
        except Exception as e:
            return {"found": False, "entries": [], "error": str(e)}


async def _ai_zero_day_analysis(
    software: str, version: str, nvd_data: dict, kev_data: dict, api_key: str
) -> dict:
    cve_summary = ", ".join(c["id"] for c in nvd_data.get("recent_cves", [])[:5]) or "none found"
    kev_summary = "YES - in CISA KEV" if kev_data.get("found") else "No known exploited CVEs"

    prompt = f"""You are a zero-day vulnerability prediction expert. Analyze the following software for zero-day risk.

Software: {software}
Version: {version or 'unknown'}
Recent CVEs: {cve_summary}
CISA KEV status: {kev_summary}
Total known CVEs: {nvd_data.get('total', 0)}

Analyze and respond in JSON format:
{{
  "risk_score": <0.0-1.0 float>,
  "risk_level": "<low|medium|high|critical>",
  "vulnerability_classes": ["<class1>", "<class2>"],
  "threat_actors": ["<actor1>", "<actor2>"],
  "tte_days": <estimated days to exploit 0-365>,
  "indicators": ["<indicator1>", "<indicator2>"],
  "recommendations": ["<rec1>", "<rec2>", "<rec3>"],
  "confidence": <0.0-1.0 float>,
  "reasoning": "<brief explanation>"
}}"""

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            r = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": GROQ_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                    "max_tokens": 800,
                },
            )
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"]
            # Extract JSON from response
            import re
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                return json.loads(json_match.group())
        except Exception:
            pass
    return _heuristic_analysis(software, nvd_data, kev_data)


def _heuristic_analysis(software: str, nvd_data: dict, kev_data: dict) -> dict:
    score = 0.2
    indicators = []
    vuln_classes = []

    total_cves = nvd_data.get("total", 0)
    if total_cves > 50:
        score += 0.2
        indicators.append(f"High CVE count: {total_cves} known vulnerabilities")
    elif total_cves > 20:
        score += 0.1
        indicators.append(f"Moderate CVE count: {total_cves} known vulnerabilities")

    if kev_data.get("found"):
        score += 0.35
        indicators.append("Software appears in CISA Known Exploited Vulnerabilities catalog")

    sw_lower = software.lower()
    for category, keywords in ZERO_DAY_INDICATORS.items():
        if any(kw in sw_lower for kw in keywords):
            score += 0.15
            vuln_classes.append(category.replace("_", " ").title())

    high_cvss = [c for c in nvd_data.get("recent_cves", []) if (c.get("score") or 0) >= 8.0]
    if high_cvss:
        score += 0.1
        indicators.append(f"{len(high_cvss)} critical/high severity CVEs found")

    score = min(score, 1.0)

    if score >= 0.7:
        risk_level = "critical"
        tte = 14
    elif score >= 0.5:
        risk_level = "high"
        tte = 60
    elif score >= 0.3:
        risk_level = "medium"
        tte = 180
    else:
        risk_level = "low"
        tte = 365

    return {
        "risk_score": round(score, 3),
        "risk_level": risk_level,
        "vulnerability_classes": vuln_classes or ["Memory Corruption", "Logic Flaws"],
        "threat_actors": ["APT Groups", "Ransomware Operators"] if score > 0.5 else ["Script Kiddies"],
        "tte_days": tte,
        "indicators": indicators,
        "recommendations": [
            "Apply all available patches immediately",
            "Enable application-level monitoring and logging",
            "Implement network segmentation to limit blast radius",
            "Subscribe to vendor security advisories",
            "Configure WAF rules for known attack patterns",
        ],
        "confidence": 0.55,
    }


def list_predictions() -> list:
    return _load_predictions()


async def trending_threats() -> dict:
    """Fetch trending threats from CISA KEV."""
    async with httpx.AsyncClient(timeout=20) as client:
        try:
            r = await client.get(CISA_KEV_URL)
            r.raise_for_status()
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            recent = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)[:10]
            return {
                "trending": [
                    {
                        "cve_id": v.get("cveID"),
                        "product": v.get("product"),
                        "vendor": v.get("vendorProject"),
                        "date_added": v.get("dateAdded"),
                        "short_description": v.get("shortDescription", "")[:200],
                        "required_action": v.get("requiredAction"),
                        "due_date": v.get("dueDate"),
                    }
                    for v in recent
                ],
                "total_kev": len(vulns),
                "fetched_at": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            return {"error": str(e), "trending": []}
