import asyncio
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional
from config import WORDLIST_PATH, MAX_THREADS


def _resolve(subdomain: str) -> Optional[str]:
    try:
        ip = socket.gethostbyname(subdomain)
        return ip
    except Exception:
        return None


def enumerate_subdomains(domain: str, progress_cb: Optional[Callable] = None) -> list:
    wordlist = []
    if WORDLIST_PATH.exists():
        wordlist = [l.strip() for l in WORDLIST_PATH.read_text().splitlines() if l.strip()]
    else:
        wordlist = [
            "www", "mail", "ftp", "admin", "dev", "test", "staging", "api",
            "app", "blog", "shop", "store", "portal", "vpn", "remote",
            "webmail", "mx", "ns1", "ns2", "cdn", "static", "assets",
            "media", "img", "docs", "help", "support", "forum", "login",
            "dashboard", "panel", "cpanel", "whm", "smtp", "pop", "imap",
            "auth", "sso", "oauth", "git", "svn", "jenkins", "ci", "jira",
            "confluence", "wiki", "internal", "intranet", "extranet", "secure",
            "m", "mobile", "wap", "old", "new", "beta", "alpha", "sandbox",
            "db", "database", "sql", "mysql", "postgres", "redis", "mongo",
            "s3", "files", "upload", "download", "backup", "archive",
            "monitor", "status", "grafana", "kibana", "elasticsearch",
            "k8s", "kubernetes", "docker", "registry", "hub", "proxy",
        ]

    found = []
    subdomains = [f"{w}.{domain}" for w in wordlist]
    total = len(subdomains)

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        futures = {ex.submit(_resolve, sub): sub for sub in subdomains}
        done = 0
        for future, sub in futures.items():
            ip = future.result()
            done += 1
            if ip:
                found.append({"subdomain": sub, "ip": ip})
            if progress_cb and done % 50 == 0:
                progress_cb(done, total)

    return found
