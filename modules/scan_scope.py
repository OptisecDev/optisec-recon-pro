"""Per-scan network scope guard.

Scan authorization (web/scan_authz.py) decides *which target* an active scan
may run against; this module keeps the scan's own traffic on that target.
Without it, an authorized scan of example.com could still be walked
somewhere else: an HTTP redirect followed by a vuln scanner, a crawled form
`action`, a CNAME'd subdomain probed during enumeration.

How it works:

  * A ScanScope (allowed exact hosts, allowed domain suffixes, and the IPs
    those resolved to when the scope was built) lives in a ContextVar.
  * install_scope_guard() patches, once per process, the two choke points
    every scanner module's outbound traffic goes through:
      - requests' HTTPAdapter.send -- the last stop before a socket for the
        original request and every redirect hop (Session.request is not
        enough: requests follows redirects via resolve_redirects(), which
        calls the adapter directly);
      - socket.create_connection -- raw TCP (port scanner, nmap's socket
        fallback, deep-scan banner grabs) and http.client, which binds it at
        connection construction (subdomain HEAD probes).
    Outside a scope (no ContextVar set) both pass straight through, so
    passive modules and the rest of the app are unaffected.
  * Inside a scope, a connection to anything not covered raises
    ScopeViolationError -- a requests ConnectionError, so also an OSError --
    which every scanner already treats as "couldn't connect". The attempt is
    recorded on the scope so the scan can report it.
  * Context doesn't flow into plain ThreadPoolExecutor workers, so the
    scanner modules use ScopedThreadPoolExecutor, which runs each task in a
    copy of the submitting thread's context. asyncio.to_thread already
    copies context.

Not covered: nmap itself runs as a subprocess (it is handed only the
authorized host); asyncio-based clients such as httpx.AsyncClient, which
connect through the event loop rather than socket.create_connection (the
scanners don't use them; deep-scan HTTP fingerprinting does, but only ever
connects to the target's own resolved IP with redirects off); dnspython and
whois raw sockets (passive); and DNS rebinding between the scope's
resolution and a module's own connect-by-hostname.
"""
from __future__ import annotations

import contextvars
import ipaddress
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterable, Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

_MAX_RECORDED = 100


class ScopeViolationError(requests.exceptions.ConnectionError):
    """A scanner tried to contact a host outside the scan's authorized scope."""


def _normalize(host) -> str:
    return str(host or "").strip().strip("[]").rstrip(".").lower()


@dataclass
class ScanScope:
    hosts: frozenset = frozenset()
    suffixes: frozenset = frozenset()
    ips: frozenset = frozenset()
    blocked: list = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def allows(self, host) -> bool:
        host = _normalize(host)
        if not host:
            return False
        if host in self.hosts:
            return True
        if any(host == s or host.endswith("." + s) for s in self.suffixes):
            return True
        try:
            return str(ipaddress.ip_address(host.split("%", 1)[0])) in self.ips
        except ValueError:
            return False

    def record_block(self, what: str) -> None:
        with self._lock:
            if len(self.blocked) < _MAX_RECORDED and what not in self.blocked:
                self.blocked.append(what)


_current: contextvars.ContextVar = contextvars.ContextVar("optisec_scan_scope", default=None)


def current_scope() -> Optional[ScanScope]:
    return _current.get()


@contextmanager
def scan_scope(scope: Optional[ScanScope]):
    """Run the block inside `scope`. None is a no-op (no restriction), which
    is what a passive-only decision passes."""
    if scope is None:
        yield None
        return
    token = _current.set(scope)
    try:
        yield scope
    finally:
        _current.reset(token)


def run_in_scope(scope: Optional[ScanScope], fn, *args, **kwargs):
    """For asyncio.to_thread(run_in_scope, scope, fn, ...): sets the scope in
    the worker thread itself, then calls fn."""
    with scan_scope(scope):
        return fn(*args, **kwargs)


def _resolve(host: str) -> set:
    try:
        return {_normalize(info[4][0]) for info in socket.getaddrinfo(host, None)}
    except (OSError, UnicodeError):
        return set()


def build_scope(hosts: Iterable[str] = (), suffixes: Iterable[str] = (), resolve: Iterable[str] = ()) -> ScanScope:
    """Blocking (does DNS) -- call via asyncio.to_thread from async code.
    `resolve` lists extra in-scope names whose current IPs should also be
    allowed, e.g. the scanned host under a suffix scope."""
    hosts = frozenset(_normalize(h) for h in hosts if _normalize(h))
    suffixes = frozenset(_normalize(s) for s in suffixes if _normalize(s))
    names_only = ScanScope(hosts=hosts, suffixes=suffixes)
    ips = set()
    for name in set(hosts) | set(suffixes) | {_normalize(r) for r in resolve}:
        if name and names_only.allows(name):
            ips |= _resolve(name)
    return ScanScope(hosts=hosts, suffixes=suffixes, ips=frozenset(ips))


class ScopedThreadPoolExecutor(ThreadPoolExecutor):
    """ThreadPoolExecutor whose tasks run in a copy of the submitter's
    context, so the active scan scope follows the work into the pool.
    map() goes through submit(), so it's covered too."""

    def submit(self, fn, /, *args, **kwargs):
        return super().submit(contextvars.copy_context().run, fn, *args, **kwargs)


# ── Guard installation ───────────────────────────────────────────────────────

_install_lock = threading.Lock()
_installed = False
# The unpatched callables the guard forwards to. Module-level (rather than
# closed over) so tests can swap in fakes and exercise the guard without any
# real connection.
_original_send = None
_original_create_connection = None


def _guarded_send(self, request, *args, **kwargs):
    scope = _current.get()
    if scope is not None and not scope.allows(urlparse(request.url).hostname):
        scope.record_block(request.url)
        raise ScopeViolationError(f"blocked out-of-scope request to {request.url!r}", request=request)
    return _original_send(self, request, *args, **kwargs)


def _guarded_create_connection(address, *args, **kwargs):
    scope = _current.get()
    if scope is not None and not scope.allows(address[0]):
        target = f"{address[0]}:{address[1]}"
        scope.record_block(target)
        raise ScopeViolationError(f"blocked out-of-scope connection to {target!r}")
    return _original_create_connection(address, *args, **kwargs)


def install_scope_guard() -> None:
    """Idempotent. Installs the HTTPAdapter.send / socket.create_connection
    wrappers described in the module docstring."""
    global _installed, _original_send, _original_create_connection
    with _install_lock:
        if _installed:
            return
        _original_send = HTTPAdapter.send
        _original_create_connection = socket.create_connection
        HTTPAdapter.send = _guarded_send
        socket.create_connection = _guarded_create_connection
        _installed = True


def scope_guard_installed() -> bool:
    return HTTPAdapter.send is _guarded_send and socket.create_connection is _guarded_create_connection
