"""Username / Social Footprint — async checks across 50+ platforms.

Detection mode per platform ("status" vs "unverified") was decided from a
live check against a definitely-nonexistent username
(xzqw9847zzzznonexistent99999) run against every platform's real endpoint.
Platforms that returned a genuine HTTP 404 for that nonexistent username
are trusted for status-code-based existence detection ("status"). Platforms
that returned HTTP 200 regardless (client-rendered SPAs whose server always
serves the same shell — Instagram/TikTok/Reddit/etc. — or an unrelated page,
like the CyberChef entry, which was never a per-user URL to begin with) or
that are blocked by anti-bot protection on automated requests (Cloudflare
403/challenge — GitLab/Quora/PlayStation/Fiverr/Upwork/PyPI) are marked
"unverified": we cannot confirm existence for them automatically, so they
are never reported as FOUND, regardless of what status code they return.
"""

import asyncio

import aiohttp

TIMEOUT = aiohttp.ClientTimeout(total=10, connect=5)

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"

# (platform_name, url_template, mode)
# mode "status": a real HTTP 404 for a nonexistent account is confirmed —
#   status_code == 200 (after redirects) is trusted as "exists".
# mode "unverified": status code alone cannot be trusted (always 200
#   regardless of existence, or blocked by anti-bot protection) — never
#   reported as FOUND; the profile URL is still returned for manual review.
PLATFORMS: list[tuple] = [
    ("GitHub",        "https://github.com/{u}",                       "status"),
    ("GitLab",        "https://gitlab.com/{u}",                       "unverified"),
    ("BitBucket",     "https://bitbucket.org/{u}",                    "status"),
    ("Twitter/X",     "https://x.com/{u}",                            "status"),
    ("Instagram",     "https://www.instagram.com/{u}/",               "unverified"),
    ("TikTok",        "https://www.tiktok.com/@{u}",                  "unverified"),
    ("YouTube",       "https://www.youtube.com/@{u}",                 "status"),
    ("Twitch",        "https://www.twitch.tv/{u}",                    "unverified"),
    ("Reddit",        "https://www.reddit.com/user/{u}",              "unverified"),
    ("Pinterest",     "https://www.pinterest.com/{u}/",               "unverified"),
    ("Snapchat",      "https://www.snapchat.com/add/{u}",             "status"),
    ("Medium",        "https://medium.com/@{u}",                      "unverified"),
    ("Dev.to",        "https://dev.to/{u}",                           "status"),
    ("HackerNews",    "https://news.ycombinator.com/user?id={u}",     "status"),
    ("Pastebin",      "https://pastebin.com/u/{u}",                   "status"),
    ("Steam",         "https://steamcommunity.com/id/{u}",            "unverified"),
    ("Keybase",       "https://keybase.io/{u}",                       "status"),
    ("ProductHunt",   "https://www.producthunt.com/@{u}",             "status"),
    ("Replit",        "https://replit.com/@{u}",                      "unverified"),
    ("Linktree",      "https://linktr.ee/{u}",                        "status"),
    ("Behance",       "https://www.behance.net/{u}",                  "status"),
    ("Dribbble",      "https://dribbble.com/{u}",                     "status"),
    ("Flickr",        "https://www.flickr.com/people/{u}",            "status"),
    ("SoundCloud",    "https://soundcloud.com/{u}",                   "status"),
    ("Spotify",       "https://open.spotify.com/user/{u}",            "unverified"),
    ("Vimeo",         "https://vimeo.com/{u}",                        "status"),
    ("Codepen",       "https://codepen.io/{u}",                       "status"),
    ("HackerOne",     "https://hackerone.com/{u}",                    "status"),
    ("Bugcrowd",      "https://bugcrowd.com/{u}",                     "status"),
    ("TryHackMe",     "https://tryhackme.com/p/{u}",                  "unverified"),
    ("HackTheBox",    "https://app.hackthebox.com/users/profile/{u}", "unverified"),
    ("Telegram",      "https://t.me/{u}",                             "unverified"),
    ("VK",            "https://vk.com/{u}",                           "status"),
    ("Quora",         "https://www.quora.com/profile/{u}",            "unverified"),
    ("About.me",      "https://about.me/{u}",                         "status"),
    ("Gravatar",      "https://gravatar.com/{u}",                     "status"),
    ("StackOverflow", "https://stackoverflow.com/users/{u}",          "status"),
    ("DockerHub",     "https://hub.docker.com/u/{u}",                 "status"),
    ("NPM",           "https://www.npmjs.com/~{u}",                   "status"),
    ("PyPI",          "https://pypi.org/user/{u}/",                   "unverified"),
    ("RubyGems",      "https://rubygems.org/profiles/{u}",            "status"),
    ("Xbox",          "https://xboxgamertag.com/search/{u}",          "status"),
    ("PlayStation",   "https://psnprofiles.com/{u}",                  "unverified"),
    ("Roblox",        "https://www.roblox.com/user.aspx?username={u}", "status"),
    ("Chess.com",     "https://www.chess.com/member/{u}",             "status"),
    ("Lichess",       "https://lichess.org/@/{u}",                    "status"),
    ("Duolingo",      "https://www.duolingo.com/profile/{u}",         "unverified"),
    ("Fiverr",        "https://www.fiverr.com/{u}",                   "unverified"),
    ("Upwork",        "https://www.upwork.com/freelancers/~{u}",      "unverified"),
]

_SPA_REASON = (
    "Client-rendered page — the server returns HTTP 200 for this URL "
    "regardless of whether the account exists, so status-code detection "
    "is unreliable here."
)
_BLOCKED_REASON = (
    "Blocked by anti-bot protection (403/challenge) on automated requests — "
    "existence cannot be confirmed without a real browser session."
)

_UNVERIFIED_REASONS: dict[str, str] = {
    "GitLab": _BLOCKED_REASON,
    "Instagram": _SPA_REASON,
    "TikTok": _SPA_REASON,
    "Twitch": _SPA_REASON,
    "Reddit": _SPA_REASON,
    "Pinterest": _SPA_REASON,
    "Medium": _SPA_REASON,
    "Steam": _SPA_REASON,
    "Replit": _SPA_REASON,
    "Spotify": _SPA_REASON,
    "TryHackMe": _SPA_REASON,
    "HackTheBox": _SPA_REASON,
    "Telegram": _SPA_REASON,
    "Quora": _BLOCKED_REASON,
    "PyPI": _BLOCKED_REASON,
    "PlayStation": _BLOCKED_REASON,
    "Duolingo": _SPA_REASON,
    "Fiverr": _BLOCKED_REASON,
    "Upwork": _BLOCKED_REASON,
}


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
    mode: str,
    username: str,
) -> dict:
    url = url_tpl.format(u=username)

    if mode == "unverified":
        return {
            "platform": name,
            "url": url,
            "username": username,
            "exists": None,
            "status_code": None,
            "verified": False,
            "reason": _UNVERIFIED_REASONS.get(
                name, "Automatic existence verification is not reliable for this platform."
            ),
        }

    try:
        async with session.get(url, allow_redirects=True, ssl=False) as resp:
            exists = resp.status == 200
            return {
                "platform": name,
                "url": url,
                "username": username,
                "exists": exists,
                "status_code": resp.status,
                "verified": True,
            }
    except Exception:
        return {
            "platform": name,
            "url": url,
            "username": username,
            "exists": False,
            "status_code": None,
            "verified": True,
            "error": "timeout/unreachable",
        }


async def search_username(username: str) -> dict:
    headers = {"User-Agent": UA}
    found = []
    not_found = []
    unverified = []
    errors = []

    connector = aiohttp.TCPConnector(limit=30, ssl=False)
    async with aiohttp.ClientSession(
        headers=headers, timeout=TIMEOUT, connector=connector
    ) as session:
        tasks = [
            _check_platform(session, name, url_tpl, mode, username)
            for name, url_tpl, mode in PLATFORMS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, Exception):
            errors.append(str(r))
            continue
        if r["exists"] is None:
            unverified.append(r)
        elif r["exists"]:
            found.append(r)
        elif r.get("error"):
            errors.append(f"{r['platform']}: {r['error']}")
        else:
            not_found.append(r)

    # Only confirmed (status-verified) hits contribute to risk scoring —
    # unverified platforms are never treated as evidence of an account.
    risk_score = min(len(found) * 8, 95)

    return {
        "username": username,
        "found": found,
        "not_found_count": len(not_found),
        "unverified": unverified,
        "unverified_count": len(unverified),
        "unverified_note": (
            "These platforms could not be automatically confirmed (client-rendered "
            "pages that always return HTTP 200, or anti-bot protection blocking "
            "automated requests) and are excluded from the FOUND list and risk "
            "score — check the listed URLs manually if needed."
        ) if unverified else None,
        "platforms_checked": len(PLATFORMS),
        "platforms_verifiable": sum(1 for _, _, m in PLATFORMS if m == "status"),
        "risk_score": risk_score,
        "risk_label": "HIGH" if risk_score > 60 else "MEDIUM" if risk_score > 30 else "LOW",
        "variations": _username_variations(username)[:10],
    }
