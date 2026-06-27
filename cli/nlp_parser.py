import re
from typing import Optional

AR_COMMANDS = {
    "subdomain": [
        r"اجمع\s+(?:النطاقات\s+الفرعية|الس[بو]داومين)",
        r"ابحث\s+عن\s+(?:النطاقات\s+الفرعية|الس[بو]داومين)",
        r"(?:النطاقات\s+الفرعية|subdomain)",
    ],
    "xss": [
        r"(?:افحص|ابحث\s+عن)\s+.*(?:xss|cross.site|سكريبت)",
        r"ثغرات?\s+xss",
        r"xss",
    ],
    "sqli": [
        r"(?:افحص|ابحث\s+عن)\s+.*(?:sql|حقن|injection)",
        r"ثغرات?\s+sql",
        r"حقن\s+(?:قاعدة\s+البيانات|sql)",
    ],
    "ssrf": [
        r"(?:افحص|ابحث\s+عن)\s+.*ssrf",
        r"ثغرات?\s+ssrf",
        r"ssrf",
    ],
    "lfi": [
        r"(?:افحص|ابحث\s+عن)\s+.*(?:lfi|ملفات\s+محلية)",
        r"ثغرات?\s+lfi",
        r"lfi",
    ],
    "redirect": [
        r"(?:افحص|ابحث\s+عن)\s+.*(?:redirect|إعادة\s+توجيه)",
        r"open\s+redirect",
        r"إعادة\s+توجيه\s+مفتوحة",
    ],
    "dns": [
        r"(?:dns|نظام\s+أسماء\s+النطاقات)",
        r"سجلات?\s+(?:dns|النطاق)",
        r"استعلام\s+dns",
    ],
    "whois": [
        r"whois",
        r"معلومات?\s+(?:التسجيل|النطاق|الدومين)",
        r"من\s+(?:يملك|سجّل)",
    ],
    "nmap": [
        r"(?:nmap|فحص\s+(?:المنافذ|الخدمات|البورتات))",
        r"منافذ\s+مفتوحة",
        r"port\s+scan",
    ],
    "email": [
        r"(?:ايميلات|بريد\s+إلكتروني|emails?)",
        r"اجمع\s+.*(?:ايميلات|بريد|emails?)",
    ],
    "social": [
        r"(?:social\s+media|وسائل\s+التواصل\s+الاجتماعي|حسابات\s+التواصل)",
        r"اجمع\s+.*(?:حسابات|social)",
    ],
    "osint": [
        r"osint",
        r"(?:استخبارات|معلومات\s+مفتوحة)",
        r"اجمع\s+(?:كل\s+)?(?:المعلومات|البيانات)",
    ],
    "full_scan": [
        r"فحص\s+(?:شامل|كامل|كل\s+شيء)",
        r"(?:ابدأ|قم\s+بـ?)\s+(?:فحص\s+شامل|full\s+scan)",
        r"full\s+scan",
        r"scan\s+all",
        r"افحص\s+(?:كل\s+شيء|شامل)",
    ],
    "report": [
        r"(?:أنشئ|اصنع|اعمل)\s+(?:تقرير|report)",
        r"report",
        r"تقرير",
    ],
    "add_target": [
        r"أضف\s+(?:الهدف|هدف|target)",
        r"(?:add|أضف)\s+target",
        r"سجّل\s+(?:الهدف|موقع)",
    ],
    "list_targets": [
        r"(?:عرض|اعرض|أظهر)\s+(?:الأهداف|targets?)",
        r"list\s+targets?",
        r"قائمة\s+الأهداف",
    ],
    "recon": [
        r"(?:استطلاع|recon|reconnaissance)",
        r"اجمع\s+(?:معلومات|بيانات)\s+عن",
        r"افحص\s+(?!\s*ثغر)",
    ],
}

EN_COMMANDS = {
    "subdomain": [r"(?:sub)?domain[s]?\s+(?:enum|scan|find|discover)", r"find\s+subdomains?"],
    "xss": [r"\bxss\b", r"cross.site\s+scripting"],
    "sqli": [r"\bsqli?\b", r"sql\s+injection"],
    "ssrf": [r"\bssrf\b"],
    "lfi": [r"\blfi\b", r"local\s+file\s+inclus"],
    "redirect": [r"open\s+redirect", r"redirect\s+vuln"],
    "dns": [r"\bdns\b", r"dns\s+lookup", r"dns\s+records?"],
    "whois": [r"\bwhois\b"],
    "nmap": [r"\bnmap\b", r"port\s+scan"],
    "email": [r"(?:find|gather|collect)\s+emails?", r"email\s+(?:harvest|finder)"],
    "social": [r"social\s+(?:media|profiles?)", r"(?:find|gather)\s+social"],
    "osint": [r"\bosint\b", r"open.source\s+intel"],
    "full_scan": [r"full\s+scan", r"complete\s+scan", r"scan\s+everything", r"comprehensive\s+scan"],
    "report": [r"(?:generate|create|make)\s+(?:a\s+)?report", r"\breport\b"],
    "add_target": [r"add\s+(?:target|domain|host)", r"new\s+target"],
    "list_targets": [r"list\s+targets?", r"show\s+targets?"],
    "recon": [r"\brecon\b", r"reconnaissance"],
}

DOMAIN_PATTERN = re.compile(
    r"(?:https?://)?(?:www\.)?([a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)"
)

FOR_PREPOSITIONS = re.compile(
    r"(?:لـ?|عن|على|of|for|against|on|at|targeting?)\s+", re.IGNORECASE
)


def detect_language(text: str) -> str:
    arabic_chars = sum(1 for c in text if '؀' <= c <= 'ۿ')
    return "ar" if arabic_chars > 2 else "en"


def extract_domain(text: str) -> str:
    cleaned = FOR_PREPOSITIONS.sub(" ", text)
    m = DOMAIN_PATTERN.search(cleaned)
    if m:
        return m.group(1).lower()
    return ""


def parse_command(text: str) -> dict:
    text_lower = text.lower().strip()
    lang = detect_language(text)
    domain = extract_domain(text)

    command_map = AR_COMMANDS if lang == "ar" else EN_COMMANDS

    detected = []
    for action, patterns in command_map.items():
        for pat in patterns:
            if re.search(pat, text_lower, re.IGNORECASE):
                detected.append(action)
                break

    if not detected:
        for action, patterns in (EN_COMMANDS if lang == "ar" else AR_COMMANDS).items():
            for pat in patterns:
                if re.search(pat, text_lower, re.IGNORECASE):
                    detected.append(action)
                    break

    action = detected[0] if detected else "unknown"

    return {
        "action": action,
        "target": domain,
        "language": lang,
        "raw": text,
        "all_detected": detected,
    }
