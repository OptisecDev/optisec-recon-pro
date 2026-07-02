"""
AI Threat Narrative — Groq-generated executive threat report.

Turns raw scan_results + MITRE ATT&CK mapping + CVE intelligence into a
structured, PTES/OWASP/MITRE-ATT&CK-style narrative for a human reader
(both English and Arabic). Uses Groq's configured model (config.GROQ_MODEL,
same model as modules/ai/groq_analyzer.py) the same way the rest of the
codebase's AI features do — sync client call, no network access of its
own beyond the Groq API.

This is the only module in the Vulnerability Intelligence feature set
that involves an LLM; map_service_to_cves() and map_finding_to_attack()
are both fully deterministic. Degrades gracefully (available=False, with
a clear `error`) whenever the groq package, GROQ_API_KEY, or the request/
response itself isn't usable — callers should never need to except
around this module.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from config import GROQ_API_KEY, GROQ_MODEL
from modules.ai.groq_client_utils import call_groq_sync_with_retry

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

logger = logging.getLogger("osint.threat_narrative")

_SYSTEM_PROMPT = "أنت محلل تهديدات سيبرانية خبير بمعايير PTES وOWASP وMITRE ATT&CK."

_MAX_TOKENS = 2000
_TEMPERATURE = 0.3
_MAX_PAYLOAD_CHARS = 4000

_RESPONSE_SCHEMA_EXAMPLE = {
    "executive_summary_en": "3 sentences in English",
    "executive_summary_ar": "3 جمل بالعربي",
    "top_3_findings": [
        {"title": "...", "severity": "Critical|High|Medium|Low", "explanation": "...", "recommendation": "..."},
    ],
    "most_likely_attack_vector": "the most probable attack scenario",
    "remediation_roadmap": {
        "critical": ["immediate - within 24 hours"],
        "high": ["within a week"],
        "medium": ["within a month"],
    },
    "overall_risk_rating": "Critical|High|Medium|Low",
    "risk_justification": "why this rating was chosen",
}

_REQUIRED_KEYS = tuple(_RESPONSE_SCHEMA_EXAMPLE)


def _client() -> "Groq":
    if not GROQ_AVAILABLE:
        raise RuntimeError("groq package not installed. Run: pip install groq")
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY environment variable not set")
    return Groq(api_key=GROQ_API_KEY)


def _truncate_for_prompt(data: Any, max_chars: int = _MAX_PAYLOAD_CHARS) -> Any:
    """Keep the prompt within a sane token budget — scan_results/
    mitre_mapping/cve_results can each be large; a truncated preview is
    still enough context for the model's summary/roadmap."""
    try:
        text = json.dumps(data, ensure_ascii=False, default=str)
    except TypeError:
        text = str(data)
    if len(text) <= max_chars:
        return data
    return {"_truncated": True, "_preview": text[:max_chars]}


def _build_user_prompt(scan_results: dict, mitre_mapping: Any, cve_results: Any) -> str:
    payload = {
        "scan_results": _truncate_for_prompt(scan_results),
        "mitre_attack_mapping": _truncate_for_prompt(mitre_mapping),
        "cve_intelligence": _truncate_for_prompt(cve_results),
    }
    return (
        "بناءً على بيانات الفحص الأمني التالية، أنشئ تقرير استخبارات تهديدات "
        "بصيغة JSON فقط دون أي نص خارج كائن JSON، متبعًا هذا الهيكل بالضبط "
        "(القيم أدناه توضيحية فقط):\n\n"
        f"{json.dumps(_RESPONSE_SCHEMA_EXAMPLE, ensure_ascii=False, indent=2)}\n\n"
        "بيانات الفحص:\n"
        f"{json.dumps(payload, ensure_ascii=False, indent=2, default=str)}"
    )


def _parse_narrative_json(content: str | None) -> dict | None:
    if not content:
        return None
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    # Some models wrap the JSON object in prose despite explicit
    # instructions and response_format={"type": "json_object"} — recover
    # the embedded object by slicing from the first "{" to the last "}"
    # (mirrors the intent of groq_analyzer.py's natural_language_to_command()
    # fallback for malformed responses).
    start, end = content.find("{"), content.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(content[start:end + 1])
    except json.JSONDecodeError:
        return None


def _fallback_narrative(error: str) -> dict:
    return {
        "executive_summary_en": "AI threat narrative unavailable.",
        "executive_summary_ar": "تحليل التهديد بالذكاء الاصطناعي غير متاح.",
        "top_3_findings": [],
        "most_likely_attack_vector": None,
        "remediation_roadmap": {"critical": [], "high": [], "medium": []},
        "overall_risk_rating": "Unknown",
        "risk_justification": None,
        "available": False,
        "error": error,
    }


def generate_threat_narrative(scan_results: dict, mitre_mapping: Any, cve_results: Any) -> dict:
    """
    Ask Groq (config.GROQ_MODEL, temperature 0.3, max 2000 tokens)
    to turn `scan_results` + `mitre_mapping` (map_finding_to_attack()/
    generate_attack_path() output) + `cve_results`
    (map_service_to_cves() output) into a structured threat narrative.

    Returns a dict with the keys: executive_summary_en,
    executive_summary_ar, top_3_findings, most_likely_attack_vector,
    remediation_roadmap, overall_risk_rating, risk_justification, plus
    `available`/`error`. Never raises — any failure (missing package/key,
    request error, unparseable response) degrades to
    available=False with `error` explaining why, using the same schema
    with empty/placeholder values so callers can render it unconditionally.
    """
    try:
        client = _client()
    except RuntimeError as exc:
        return _fallback_narrative(str(exc))

    user_prompt = _build_user_prompt(scan_results or {}, mitre_mapping or {}, cve_results or {})
    try:
        response = call_groq_sync_with_retry(
            client.chat.completions.create,
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=_MAX_TOKENS,
            temperature=_TEMPERATURE,
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content
    except Exception as exc:
        logger.error("[threat_narrative] Groq request failed: %s", exc)
        return _fallback_narrative(f"Groq request failed: {exc}")

    narrative = _parse_narrative_json(content)
    if narrative is None:
        logger.error("[threat_narrative] could not parse Groq response as JSON")
        return _fallback_narrative("Groq returned a response that could not be parsed as JSON")

    fallback_defaults = _fallback_narrative("")
    for key in _REQUIRED_KEYS:
        narrative.setdefault(key, fallback_defaults[key])
    narrative["available"] = True
    narrative["error"] = None
    return narrative
