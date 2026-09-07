"""Lightweight, same-origin crawler shared by the vuln scanners.

Before this module existed, every scan_*(url) in xss.py/sqli.py/lfi.py/
ssrf.py/open_redirect.py only ever tested the single URL it was handed: its
own query-string params (or a generic guessed {"q": "test", "id": "1"} when
there was none) and — for xss.py/sqli.py only — the forms present on that
one page. A target whose actual vulnerable parameters live on pages one or
two links away from the scanned URL (e.g. testphp.vulnweb.com's real surface
is on listproducts.php?cat=, artists.php?artist=, search.php, guestbook.php —
none of which are the root page) was scanned as if it had zero real
parameters, and every finding came from the generic guess instead of a real
sink — the false-negative half of the bug this module fixes.

`crawl()` does a small, bounded, same-origin BFS from the scan target and
collects every internal link's query-string and every <form>'s real
name/value inputs across all discovered pages, so callers (web/app.py,
cli/commands.py) can hand scanners real attack surface instead of guesses.
"""

import urllib.robotparser
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

from config import DEFAULT_TIMEOUT

CRAWL_USER_AGENT = "OPTISEC-ReconPro/1.0 (Security Testing)"

# Depth/page caps exist purely to keep a "quick scan" quick: this is recon
# for vuln testing, not a general-purpose site crawler. Two hops from the
# scanned URL reaches virtually every page linked from a target's own nav
# menu without risking a slow crawl of a large site.
DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_PAGES = 25

# Extensions that are never worth fetching as an HTML page — following them
# wastes a request and (for binaries) risks feeding garbage bytes to
# BeautifulSoup for zero benefit, since none of these can contain a <form>
# or a same-origin <a href> we don't already have another route to.
_SKIP_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css", ".js",
    ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz", ".mp4",
    ".mp3", ".avi", ".mov", ".doc", ".docx", ".xls", ".xlsx",
)

_SKIP_INPUT_TYPES = {"submit", "button", "image", "reset", "file", "checkbox", "radio"}


@dataclass
class CrawledForm:
    url: str
    method: str
    inputs: dict


@dataclass
class CrawlResult:
    urls: list = field(default_factory=list)   # same-origin URLs with a real query string
    forms: list = field(default_factory=list)  # list[CrawledForm]


def _same_origin(base_netloc: str, candidate: str) -> bool:
    try:
        return urlparse(candidate).netloc == base_netloc
    except ValueError:
        return False


def _is_crawlable(url: str) -> bool:
    path = urlparse(url).path.lower()
    return not path.endswith(_SKIP_EXTENSIONS)


def _load_robots(base_url: str, session: requests.Session) -> "urllib.robotparser.RobotFileParser | None":
    """Best-effort robots.txt fetch. Returns None (meaning "no restriction
    known") on any failure — a missing/unreachable robots.txt must never
    block a scan the user explicitly asked us to run against a target they
    already control or are authorized to test."""
    try:
        robots_url = urljoin(base_url, "/robots.txt")
        resp = session.get(robots_url, timeout=DEFAULT_TIMEOUT)
        if resp.status_code != 200 or not resp.text.strip():
            return None
        rp = urllib.robotparser.RobotFileParser()
        rp.parse(resp.text.splitlines())
        return rp
    except Exception:
        return None


def _extract_forms(soup: BeautifulSoup, page_url: str) -> list:
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "get").lower()
        form_url = urljoin(page_url, action)

        inputs = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "text").lower()
            if itype in _SKIP_INPUT_TYPES:
                continue
            if inp.name == "select":
                option = inp.find("option", selected=True) or inp.find("option")
                value = option.get("value", option.get_text(strip=True)) if option else "test"
            else:
                value = inp.get("value") or "test"
            inputs[name] = value

        if inputs:
            forms.append(CrawledForm(url=form_url, method=method, inputs=inputs))
    return forms


def crawl(
    base_url: str,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_pages: int = DEFAULT_MAX_PAGES,
) -> CrawlResult:
    """Breadth-first, same-origin crawl starting at `base_url`.

    Collects (a) every same-origin URL encountered (including `base_url`
    itself) that carries a real query string, and (b) every <form> found on
    any discovered page with its real field names/values. Both feed
    scanners real attack surface instead of a single-page guess.
    """
    session = requests.Session()
    session.headers["User-Agent"] = CRAWL_USER_AGENT

    base_netloc = urlparse(base_url).netloc
    robots = _load_robots(base_url, session)

    seen_pages = set()
    seen_urls_with_params = set()
    result = CrawlResult()

    queue = [(base_url, 0)]

    while queue and len(seen_pages) < max_pages:
        page_url, depth = queue.pop(0)
        if page_url in seen_pages:
            continue
        seen_pages.add(page_url)

        if robots is not None:
            try:
                if not robots.can_fetch(CRAWL_USER_AGENT, page_url):
                    continue
            except Exception:
                pass

        try:
            resp = session.get(page_url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        except Exception:
            continue

        content_type = resp.headers.get("Content-Type", "")
        if "html" not in content_type and content_type:
            continue

        if parse_qs(urlparse(page_url).query) and page_url not in seen_urls_with_params:
            seen_urls_with_params.add(page_url)
            result.urls.append(page_url)

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            continue

        result.forms.extend(_extract_forms(soup, page_url))

        if depth >= max_depth:
            continue

        for a in soup.find_all("a", href=True):
            link = urljoin(page_url, a["href"].split("#")[0])
            if not link.startswith(("http://", "https://")):
                continue
            if not _same_origin(base_netloc, link):
                continue
            if not _is_crawlable(link):
                continue
            if link not in seen_pages:
                queue.append((link, depth + 1))

    return result
