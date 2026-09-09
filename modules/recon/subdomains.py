import http.client
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional
from config import WORDLIST_PATH, MAX_THREADS
from modules.recon.ssl_analysis import _parse_cert_der

# Short and deliberately tight: this only needs to distinguish "something is
# actually listening and answering as this exact host" from "DNS resolved
# but nothing is there" (wildcard-DNS domains like *.github.io/*.vercel.app
# resolve for literally any guess). Kept well under the per-request timeouts
# used elsewhere (DEFAULT_TIMEOUT=5s) so a wildcard-DNS target — where every
# wordlist guess resolves and needs probing — still finishes comfortably
# inside the subdomain step's overall 40s budget at MAX_THREADS concurrency.
_PROBE_TIMEOUT = 2.5


def _resolve(subdomain: str) -> Optional[str]:
    try:
        ip = socket.gethostbyname(subdomain)
        return ip
    except Exception:
        return None


def _hostname_matches_san(hostname: str, sans: list) -> bool:
    hostname = hostname.lower().rstrip(".")
    for san in sans:
        san = str(san).lower().rstrip(".")
        if san == hostname:
            return True
        if san.startswith("*."):
            host_parent = hostname.split(".", 1)[1] if "." in hostname else ""
            if host_parent and host_parent == san[2:]:
                return True
    return False


def _tls_san_check(hostname: str) -> Optional[bool]:
    """True: handshake succeeded and the cert actually covers this hostname.
    False: handshake succeeded but the cert's SAN list does NOT cover this
    hostname — the decisive wildcard-DNS tell (e.g. GitHub Pages' cert for
    `optisecdev.github.io` never lists `grafana.optisecdev.github.io`, even
    though that name resolves via the shared wildcard A records).
    None: no handshake could be completed at all (refused/timeout/no TLS on
    this host) — inconclusive, caller should fall back to an HTTP probe
    rather than treating "couldn't connect on 443" as a rejection.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, 443), timeout=_PROBE_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except Exception:
        return None
    if not der:
        return None
    sans = _parse_cert_der(der).get("sans") or []
    if not sans:
        return None
    return _hostname_matches_san(hostname, sans)


def _http_head_check(hostname: str) -> Optional[bool]:
    """Fallback for hosts with no TLS at all on 443. True: got a real HTTP
    response that isn't a generic 404 (2xx/3xx, or an app-level 4xx/5xx like
    401/403/500 — still evidence of a real server behind the name). False: a
    plain 404, the generic "nothing registered for this host" page most
    wildcard-DNS PaaS providers return. None: couldn't even connect — no
    signal either way.
    """
    try:
        conn = http.client.HTTPConnection(hostname, 80, timeout=_PROBE_TIMEOUT)
        try:
            conn.request("HEAD", "/")
            status = conn.getresponse().status
        finally:
            conn.close()
    except Exception:
        return None
    return status != 404


def _verify_live_host(hostname: str) -> tuple:
    """Returns (confirmed: bool, reason: str). Only a positive TLS-SAN match
    or a non-404 HTTP response counts as confirmed; everything else —
    including a probe that couldn't connect at all — is kept out of the
    confirmed bucket but tagged with *why*, so an inconclusive network
    hiccup ("probe_failed") is never conflated with a decisive rejection
    ("tls_san_mismatch" / "http_404") and nothing is silently discarded.
    """
    tls_result = _tls_san_check(hostname)
    if tls_result is True:
        return True, "tls_san"
    if tls_result is False:
        return False, "tls_san_mismatch"

    http_result = _http_head_check(hostname)
    if http_result is True:
        return True, "http"
    if http_result is False:
        return False, "http_404"

    return False, "probe_failed"


def enumerate_subdomains(domain: str, progress_cb: Optional[Callable] = None) -> dict:
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

    resolved = []
    subdomains = [f"{w}.{domain}" for w in wordlist]
    total = len(subdomains)

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        futures = {ex.submit(_resolve, sub): sub for sub in subdomains}
        done = 0
        for future, sub in futures.items():
            ip = future.result()
            done += 1
            if ip:
                resolved.append({"subdomain": sub, "ip": ip})
            if progress_cb and done % 50 == 0:
                progress_cb(done, total)

    # A resolved A record only proves DNS answered — on wildcard-DNS domains
    # (GitHub Pages, Vercel, Netlify, Heroku, etc.) that's true for every
    # guess regardless of whether anything real is hosted there. Confirm
    # each hit actually has a live, distinctly-addressed host behind it
    # before counting it.
    confirmed = []
    unconfirmed = []
    if resolved:
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
            futures = {ex.submit(_verify_live_host, r["subdomain"]): r for r in resolved}
            for future, r in futures.items():
                is_live, reason = future.result()
                if is_live:
                    confirmed.append({**r, "verified_via": reason})
                else:
                    unconfirmed.append({**r, "reason": reason})

    return {"subdomains": confirmed, "unconfirmed": unconfirmed}
