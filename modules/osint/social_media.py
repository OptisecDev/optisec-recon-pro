import re
import requests
from bs4 import BeautifulSoup
from config import DEFAULT_TIMEOUT

SOCIAL_PATTERNS = {
    "twitter": r"(?:twitter\.com|x\.com)/([A-Za-z0-9_]{1,50})",
    "linkedin": r"linkedin\.com/(?:in|company)/([A-Za-z0-9\-_]+)",
    "facebook": r"facebook\.com/([A-Za-z0-9.\-_]+)",
    "instagram": r"instagram\.com/([A-Za-z0-9._]+)",
    "github": r"github\.com/([A-Za-z0-9\-]+)",
    "youtube": r"youtube\.com/(?:c/|channel/|user/)?([A-Za-z0-9\-_]+)",
    "telegram": r"t\.me/([A-Za-z0-9_]+)",
    "discord": r"discord\.(?:gg|com/invite)/([A-Za-z0-9]+)",
}


def find_social_profiles(domain: str) -> dict:
    results = {platform: [] for platform in SOCIAL_PATTERNS}
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (compatible; OPTISEC/1.0)"

    urls = [
        f"https://{domain}",
        f"https://www.{domain}",
        f"https://{domain}/about",
        f"https://{domain}/contact",
    ]

    all_text = ""
    for url in urls:
        try:
            r = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            all_text += r.text + " "
        except Exception:
            continue

    for platform, pattern in SOCIAL_PATTERNS.items():
        matches = re.findall(pattern, all_text, re.IGNORECASE)
        seen = set()
        for match in matches:
            clean = match.strip("/").lower()
            if clean and clean not in seen and clean not in ("share", "sharer", "intent", "home"):
                seen.add(clean)
                results[platform].append(clean)

    return {
        "domain": domain,
        "profiles": {k: v for k, v in results.items() if v},
    }
