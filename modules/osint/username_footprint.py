"""Username / Social Footprint — async checks across 50+ platforms."""

import asyncio
import re
from typing import Optional

import aiohttp

TIMEOUT = aiohttp.ClientTimeout(total=10, connect=5)

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"

# (platform_name, url_template, claim_code)
# claim_code: 200 = exists on 200 OK, 404 = exists when NOT 404, neg404 = exists on non-404
PLATFORMS: list[tuple] = [
    ("GitHub",        "https://github.com/{u}",                       200),
    ("GitLab",        "https://gitlab.com/{u}",                       200),
    ("BitBucket",     "https://bitbucket.org/{u}",                    200),
    ("Twitter/X",     "https://x.com/{u}",                            200),
    ("Instagram",     "https://www.instagram.com/{u}/",               200),
    ("TikTok",        "https://www.tiktok.com/@{u}",                  200),
    ("YouTube",       "https://www.youtube.com/@{u}",                 200),
    ("Twitch",        "https://www.twitch.tv/{u}",                    200),
    ("Reddit",        "https://www.reddit.com/user/{u}",              200),
    ("Pinterest",     "https://www.pinterest.com/{u}/",               200),
    ("Snapchat",      "https://www.snapchat.com/add/{u}",             200),
    ("Medium",        "https://medium.com/@{u}",                      200),
    ("Dev.to",        "https://dev.to/{u}",                           200),
    ("HackerNews",    "https://news.ycombinator.com/user?id={u}",     200),
    ("Pastebin",      "https://pastebin.com/u/{u}",                   200),
    ("Steam",         "https://steamcommunity.com/id/{u}",            200),
    ("Keybase",       "https://keybase.io/{u}",                       200),
    ("ProductHunt",   "https://www.producthunt.com/@{u}",             200),
    ("Replit",        "https://replit.com/@{u}",                      200),
    ("Linktree",      "https://linktr.ee/{u}",                        200),
    ("Behance",       "https://www.behance.net/{u}",                  200),
    ("Dribbble",      "https://dribbble.com/{u}",                     200),
    ("Flickr",        "https://www.flickr.com/people/{u}",            200),
    ("SoundCloud",    "https://soundcloud.com/{u}",                   200),
    ("Spotify",       "https://open.spotify.com/user/{u}",            200),
    ("Vimeo",         "https://vimeo.com/{u}",                        200),
    ("Codepen",       "https://codepen.io/{u}",                       200),
    ("HackerOne",     "https://hackerone.com/{u}",                    200),
    ("Bugcrowd",      "https://bugcrowd.com/{u}",                     200),
    ("TryHackMe",     "https://tryhackme.com/p/{u}",                  200),
    ("HackTheBox",    "https://app.hackthebox.com/users/profile/{u}", 200),
    ("CyberChef",     "https://gchq.github.io/CyberChef/",           200),
    ("Telegram",      "https://t.me/{u}",                             200),
    ("VK",            "https://vk.com/{u}",                           200),
    ("Quora",         "https://www.quora.com/profile/{u}",            200),
    ("About.me",      "https://about.me/{u}",                         200),
    ("Gravatar",      "https://gravatar.com/{u}",                     200),
    ("StackOverflow", "https://stackoverflow.com/users/{u}",          200),
    ("DockerHub",     "https://hub.docker.com/u/{u}",                 200),
    ("NPM",           "https://www.npmjs.com/~{u}",                   200),
    ("PyPI",          "https://pypi.org/user/{u}/",                   200),
    ("RubyGems",      "https://rubygems.org/profiles/{u}",            200),
    ("Xbox",          "https://xboxgamertag.com/search/{u}",          200),
    ("PlayStation",   "https://psnprofiles.com/{u}",                  200),
    ("Roblox",        "https://www.roblox.com/user.aspx?username={u}", 200),
    ("Chess.com",     "https://www.chess.com/member/{u}",             200),
    ("Lichess",       "https://lichess.org/@/{u}",                    200),
    ("Duolingo",      "https://www.duolingo.com/profile/{u}",         200),
    ("Fiverr",        "https://www.fiverr.com/{u}",                   200),
    ("Upwork",        "https://www.upwork.com/freelancers/~{u}",      200),
]


def _username_variations(username: str) -> list[str]:
    """Generate common username variations."""
    base = username.lower()
    variants = {base}
    # with dots, underscores, dashes
    for sep in (".", "_", "-"):
        for i in range(1, len(base)):
            variants.add(base[:i] + sep + base[i:])
    # common numeric suffixes
    for n in ("1", "2", "123", "0", "99"):
        variants.add(base + n)
    variants.discard(base)
    return [base] + sorted(list(variants))[:15]


async def _check_platform(
    session: aiohttp.ClientSession,
    name: str,
    url_tpl: str,
    claim_code: int,
    username: str,
) -> Optional[dict]:
    url = url_tpl.format(u=username)
    try:
        async with session.get(url, allow_redirects=True, ssl=False) as resp:
            exists = resp.status == claim_code
            return {
                "platform": name,
                "url": url,
                "username": username,
                "exists": exists,
                "status_code": resp.status,
            }
    except Exception:
        return {
            "platform": name,
            "url": url,
            "username": username,
            "exists": False,
            "status_code": None,
            "error": "timeout/unreachable",
        }


async def search_username(username: str) -> dict:
    headers = {"User-Agent": UA}
    found = []
    not_found = []
    errors = []

    connector = aiohttp.TCPConnector(limit=30, ssl=False)
    async with aiohttp.ClientSession(
        headers=headers, timeout=TIMEOUT, connector=connector
    ) as session:
        tasks = [
            _check_platform(session, name, url_tpl, code, username)
            for name, url_tpl, code in PLATFORMS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, Exception):
            errors.append(str(r))
            continue
        if r["exists"]:
            found.append(r)
        elif r.get("error"):
            errors.append(f"{r['platform']}: {r['error']}")
        else:
            not_found.append(r)

    risk_score = min(len(found) * 8, 95)

    return {
        "username": username,
        "found": found,
        "not_found_count": len(not_found),
        "platforms_checked": len(PLATFORMS),
        "risk_score": risk_score,
        "risk_label": "HIGH" if risk_score > 60 else "MEDIUM" if risk_score > 30 else "LOW",
        "variations": _username_variations(username)[:10],
    }
