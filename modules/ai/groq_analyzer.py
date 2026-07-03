import hashlib
import json
from collections import OrderedDict
from typing import Optional
from config import GROQ_API_KEY, GROQ_MODEL
from modules.ai.groq_client_utils import call_groq_sync_with_retry
from modules.ai.rate_limiter import (
    estimate_tokens_from_text,
    get_default_daily_budget,
    parse_tpd_state_from_error,
)

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

_ANALYZE_MAX_TOKENS = 400
_ANALYZE_MAX_FINDINGS_SHOWN = 5

# Simple in-memory LRU cache keyed on (findings, target, lang), so repeated
# "AI Analysis" clicks on the same scan results don't spend Groq quota twice.
_analysis_cache: "OrderedDict[str, str]" = OrderedDict()
_ANALYSIS_CACHE_MAX_SIZE = 200


def _client():
    if not GROQ_AVAILABLE:
        raise RuntimeError("groq package not installed. Run: pip install groq")
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY environment variable not set")
    return Groq(api_key=GROQ_API_KEY)


def _cache_key(findings: list, target: str, lang: str) -> str:
    payload = json.dumps({"findings": findings, "target": target, "lang": lang}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _cache_get(key: str) -> Optional[str]:
    if key not in _analysis_cache:
        return None
    _analysis_cache.move_to_end(key)
    return _analysis_cache[key]


def _cache_set(key: str, value: str) -> None:
    _analysis_cache[key] = value
    _analysis_cache.move_to_end(key)
    if len(_analysis_cache) > _ANALYSIS_CACHE_MAX_SIZE:
        _analysis_cache.popitem(last=False)


def _build_findings_summary(findings: list, lang: str = "ar") -> str:
    """Condensed type/severity/parameter summary, capped at 5 findings.

    Sending full evidence/response bodies for every finding is what drives
    prompt size (and Groq token spend) up the most; the remaining findings
    beyond the cap are folded into a single total-count line instead of
    being dropped silently.
    """
    shown = findings[:_ANALYZE_MAX_FINDINGS_SHOWN]
    remaining = len(findings) - len(shown)

    lines = [
        f"- {f.get('type', 'unknown')} | severity={f.get('severity', 'unknown')} | parameter={f.get('parameter', '')}"
        for f in shown
    ]
    summary = "\n".join(lines)

    if remaining > 0:
        if lang == "ar":
            summary += f"\n... و{remaining} ثغرة إضافية غير معروضة هنا (إجمالي الثغرات: {len(findings)})"
        else:
            summary += f"\n... and {remaining} more finding(s) not shown here (total findings: {len(findings)})"

    return summary


def generate_static_summary(findings: list, target: str, lang: str = "ar") -> str:
    """Build a non-AI summary directly from findings data.

    Used as the fallback when Groq is unreachable/exhausted entirely, so the
    user still gets something useful instead of a raw error string.
    """
    severity_counts: dict = {}
    type_counts: dict = {}
    for f in findings:
        severity = f.get("severity", "unknown")
        vuln_type = f.get("type", "unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1

    most_common_type = max(type_counts, key=type_counts.get) if type_counts else None

    if lang == "ar":
        lines = [f"ملخص تلقائي لنتائج فحص {target} (بدون ذكاء اصطناعي):", ""]
        lines.append(f"إجمالي الثغرات المكتشفة: {len(findings)}")
        lines.append("توزيع الخطورة:")
        for severity, count in sorted(severity_counts.items(), key=lambda kv: -kv[1]):
            lines.append(f"  - {severity}: {count}")
        if most_common_type:
            lines.append(f"أكثر نوع ثغرة تكراراً: {most_common_type} ({type_counts[most_common_type]} مرة)")
        lines.append("")
        lines.append("توصية عامة: راجع الثغرات الحرجة والعالية الخطورة أولاً، وطبّق الإصلاحات الموصى بها لكل نوع ثغرة قبل إعادة الفحص.")
        return "\n".join(lines)

    lines = [f"Automatic summary of scan results for {target} (no AI):", ""]
    lines.append(f"Total findings: {len(findings)}")
    lines.append("Severity breakdown:")
    for severity, count in sorted(severity_counts.items(), key=lambda kv: -kv[1]):
        lines.append(f"  - {severity}: {count}")
    if most_common_type:
        lines.append(f"Most common finding type: {most_common_type} ({type_counts[most_common_type]} occurrences)")
    lines.append("")
    lines.append("General recommendation: address critical/high severity findings first, and apply the standard remediation for each finding type before rescanning.")
    return "\n".join(lines)


def _budget_exceeded_message(lang: str) -> str:
    if lang == "ar":
        return "تم الوصول لحد الاستهلاك اليومي التقريبي لخدمة الذكاء الاصطناعي. حاول مرة أخرى لاحقاً."
    return "The estimated daily AI usage limit has been reached. Please try again later."


def analyze_findings(findings: list, target: str, lang: str = "ar") -> str:
    if not findings:
        if lang == "ar":
            return "لم يتم اكتشاف ثغرات أمنية في الفحص."
        return "No security vulnerabilities were found in the scan."

    cache_key = _cache_key(findings, target, lang)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    findings_summary = _build_findings_summary(findings, lang)

    if lang == "ar":
        prompt = f"""أنت خبير أمن معلومات متخصص في اختبار الاختراق وبرامج Bug Bounty.

الهدف: {target}

ملخص نتائج الفحص الأمني (النوع | الخطورة | المعامل):
{findings_summary}

قم بتحليل هذه النتائج وأعطِ:
1. ملخص تنفيذي موجز للثغرات المكتشفة
2. تقييم مستوى الخطورة الإجمالي
3. أهم الثغرات التي يجب معالجتها بشكل عاجل
4. توصيات إصلاح موجزة
5. نصيحة عامة للتحسين الأمني

اكتب التحليل باللغة العربية بأسلوب مهني ومختصر."""
    else:
        prompt = f"""You are a cybersecurity expert specializing in penetration testing and bug bounty programs.

Target: {target}

Security scan findings summary (type | severity | parameter):
{findings_summary}

Provide:
1. Brief executive summary of discovered vulnerabilities
2. Overall severity assessment
3. Top priority vulnerabilities requiring immediate attention
4. Concise remediation recommendations
5. General security improvement advice

Write the analysis professionally and concisely."""

    estimated_tokens = estimate_tokens_from_text(prompt, completion_tokens=_ANALYZE_MAX_TOKENS)
    budget = get_default_daily_budget()
    if budget.would_exceed(estimated_tokens):
        return _budget_exceeded_message(lang)

    try:
        client = _client()
        response = call_groq_sync_with_retry(
            client.chat.completions.create,
            model=GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=_ANALYZE_MAX_TOKENS,
            temperature=0.3,
            retry_delays=(1, 2, 4),
            # A rate_limit_exceeded (TPD) 429 is a daily cap, not a transient
            # blip — retrying seconds later can't help, so skip the
            # remaining backoff delays and fall through to the static
            # fallback immediately instead of stalling the request.
            retry_on=lambda exc: parse_tpd_state_from_error(exc) is None,
        )
        budget.record(estimated_tokens)
        result = response.choices[0].message.content
        _cache_set(cache_key, result)
        return result
    except Exception:
        return generate_static_summary(findings, target, lang)


def natural_language_to_command(text: str) -> dict:
    prompt = f"""You are an AI assistant for OPTISEC Recon Pro, a bug bounty and security testing platform.

Parse the following user input (which may be in Arabic or English) and extract:
1. The action/command to perform
2. The target domain or URL
3. Any specific scan types requested

User input: "{text}"

Respond with ONLY a JSON object with these fields:
{{
  "action": "one of: recon, subdomain, dns, whois, nmap, xss, sqli, ssrf, lfi, redirect, osint, email, social, full_scan, report, add_target, list_targets",
  "target": "the domain or URL",
  "scan_types": ["list of specific scan types if mentioned"],
  "language": "ar or en",
  "confidence": 0.0 to 1.0
}}

Examples:
- input "افحص example.com عن ثغرات XSS" -> {{"action": "xss", "target": "example.com", "scan_types": ["xss"], "language": "ar", "confidence": 0.95}}
- input "Scan tesla.com for XSS and SQLi vulnerabilities" -> {{"action": "full_scan", "target": "tesla.com", "scan_types": ["xss", "sqli"], "language": "en", "confidence": 0.95}}
- input "اجمع النطاقات الفرعية لـ tesla.com" -> {{"action": "subdomain", "target": "tesla.com", "scan_types": [], "language": "ar", "confidence": 0.95}}
- input "ابدأ فحص شامل" -> {{"action": "full_scan", "target": "", "scan_types": [], "language": "ar", "confidence": 0.95}}
- input "أضف الهدف hackerone.com" -> {{"action": "add_target", "target": "hackerone.com", "scan_types": [], "language": "ar", "confidence": 0.95}}"""

    try:
        client = _client()
        response = call_groq_sync_with_retry(
            client.chat.completions.create,
            model=GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=256,
            temperature=0.1,
            response_format={"type": "json_object"},
            # openai/gpt-oss-120b intermittently rejects this call with an
            # HTTP 400 json_validate_failed when scan_types has 2+ items
            # (observed ~12-50% depending on input language); more attempts
            # than the shared default drive residual failure near zero.
            retry_delays=(1, 2, 4, 8),
        )
        content = response.choices[0].message.content.strip()
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return {"action": "unknown", "target": "", "scan_types": [], "language": "en", "confidence": 0}
    except Exception as e:
        return {"action": "error", "target": "", "error": str(e), "language": "en", "confidence": 0}


def summarize_recon(recon_data: dict, lang: str = "ar") -> str:
    summary = json.dumps(recon_data, ensure_ascii=False, indent=2)
    if lang == "ar":
        prompt = f"لخّص نتائج الاستطلاع التالية بشكل موجز ومهني باللغة العربية:\n{summary}"
    else:
        prompt = f"Summarize these reconnaissance results concisely and professionally:\n{summary}"

    try:
        client = _client()
        response = call_groq_sync_with_retry(
            client.chat.completions.create,
            model=GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=512,
            temperature=0.3,
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error: {e}"
