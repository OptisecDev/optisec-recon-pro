import json
from typing import Optional
from config import GROQ_API_KEY, GROQ_MODEL
from modules.ai.groq_client_utils import call_groq_sync_with_retry

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False


def _client():
    if not GROQ_AVAILABLE:
        raise RuntimeError("groq package not installed. Run: pip install groq")
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY environment variable not set")
    return Groq(api_key=GROQ_API_KEY)


def analyze_findings(findings: list, target: str, lang: str = "ar") -> str:
    if not findings:
        if lang == "ar":
            return "لم يتم اكتشاف ثغرات أمنية في الفحص."
        return "No security vulnerabilities were found in the scan."

    summary = json.dumps(findings, ensure_ascii=False, indent=2)

    if lang == "ar":
        prompt = f"""أنت خبير أمن معلومات متخصص في اختبار الاختراق وبرامج Bug Bounty.

الهدف: {target}

نتائج الفحص الأمني:
{summary}

قم بتحليل هذه النتائج وأعطِ:
1. ملخص تنفيذي للثغرات المكتشفة
2. تقييم مستوى الخطورة الإجمالي
3. أهم الثغرات التي يجب معالجتها بشكل عاجل
4. توصيات الإصلاح لكل ثغرة
5. نصائح للتحسين العام في الأمان

اكتب التحليل باللغة العربية بأسلوب مهني."""
    else:
        prompt = f"""You are a cybersecurity expert specializing in penetration testing and bug bounty programs.

Target: {target}

Security scan findings:
{summary}

Provide:
1. Executive summary of discovered vulnerabilities
2. Overall severity assessment
3. Top priority vulnerabilities requiring immediate attention
4. Remediation recommendations for each vulnerability
5. General security improvement advice

Write the analysis professionally."""

    try:
        client = _client()
        response = call_groq_sync_with_retry(
            client.chat.completions.create,
            model=GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2048,
            temperature=0.3,
        )
        return response.choices[0].message.content
    except Exception as e:
        if lang == "ar":
            return f"خطأ في تحليل الذكاء الاصطناعي: {str(e)}"
        return f"AI analysis error: {str(e)}"


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
