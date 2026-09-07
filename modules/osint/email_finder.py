import re
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from config import DEFAULT_TIMEOUT

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; OPTISEC/1.0)"}


def _extract_emails(text: str) -> set:
    return set(EMAIL_RE.findall(text))


async def find_emails(domain: str) -> dict:
    found = set()
    timeout = aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)

    urls_to_check = [
        f"https://{domain}",
        f"https://{domain}/contact",
        f"https://{domain}/about",
        f"https://{domain}/team",
        f"https://www.{domain}",
    ]

    crawled = set()
    async with aiohttp.ClientSession(headers=_HEADERS, timeout=timeout) as session:
        for start_url in urls_to_check:
            try:
                async with session.get(start_url, allow_redirects=True) as r:
                    crawled.add(str(r.url))
                    text = await r.text()
                soup = BeautifulSoup(text, "html.parser")
                found |= _extract_emails(text)

                for link in soup.find_all("a", href=True):
                    href = link["href"]
                    if href.startswith("mailto:"):
                        email = href[7:].split("?")[0]
                        if "@" in email:
                            found.add(email)
                    full = urljoin(start_url, href)
                    if domain in full and full not in crawled and len(crawled) < 20:
                        try:
                            async with session.get(full) as sub_r:
                                sub_text = await sub_r.text()
                            found |= _extract_emails(sub_text)
                            crawled.add(full)
                        except Exception:
                            pass
            except Exception:
                continue

    domain_emails = {e for e in found if domain in e}
    other_emails = found - domain_emails

    return {
        "domain": domain,
        "emails": sorted(domain_emails),
        "related_emails": sorted(other_emails)[:20],
        "total": len(found),
    }
