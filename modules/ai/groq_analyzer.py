import json
from typing import Optional
from config import GROQ_API_KEY, GROQ_MODEL

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
        response = client.chat.completions.create(
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

Arabic command examples:
- "افحص example.com عن ثغرات XSS" → action: xss, target: example.com
- "اجمع النطاقات الفرعية لـ tesla.com" → action: subdomain, target: tesla.com
- "ابدأ فحص شامل" → action: full_scan
- "أضف الهدف hackerone.com" → action: add_target, target: hackerone.com"""

    try:
        client = _client()
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=256,
            temperature=0.1,
        )
        content = response.choices[0].message.content.strip()
        import re
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            return json.loads(json_match.group())
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
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=512,
            temperature=0.3,
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error: {e}"
