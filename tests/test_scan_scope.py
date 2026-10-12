"""
Coverage for modules/scan_scope.py (the per-scan network scope guard) and
the passive subdomain mode -- step 5 of scan authorization.

No real connections: the guard forwards allowed calls to
scan_scope._original_send / _original_create_connection, which every test
here replaces with a recording fake (autouse fixture). So an allowed call
shows up in the fake's log, a blocked one raises ScopeViolationError before
reaching it, and nothing ever leaves the process.
"""

import asyncio
import os
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import http.client

import pytest
import requests
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import modules.recon.port_scanner as port_scanner
import modules.recon.subdomains as subs_mod
import modules.scan_scope as ss
import web.app as app_module  # noqa: F401 -- importing the app installs the guard
import web.domain_verification as dv
from modules.vuln._concurrency import run_concurrent_scan
from web.database import Base
from web.models import Scan
from web.scan_authz import AuthzDecision, scope_targets


def _run(coro):
    return asyncio.run(coro)


def _scope(hosts=(), suffixes=(), ips=()):
    return ss.ScanScope(hosts=frozenset(hosts), suffixes=frozenset(suffixes), ips=frozenset(ips))


class _FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def close(self):
        pass


@pytest.fixture(autouse=True)
def fake_net(monkeypatch):
    """Replace what the guard forwards to; record every call that got through."""
    ss.install_scope_guard()
    log = {"send": [], "connect": []}

    def fake_send(adapter, request, *a, **k):
        log["send"].append(request.url)
        r = requests.Response()
        r.request, r.url, r.connection = request, request.url, adapter
        if request.url.endswith("/redirect-out"):
            r.status_code, r._content = 302, b""
            r.headers["Location"] = "http://evil.test/landing"
        elif request.url.endswith("/redirect-in"):
            r.status_code, r._content = 302, b""
            r.headers["Location"] = "/landing"
        else:
            r.status_code, r._content = 200, b"ok"
        return r

    def fake_connect(address, *a, **k):
        log["connect"].append(f"{address[0]}:{address[1]}")
        return _FakeSocket()

    monkeypatch.setattr(ss, "_original_send", fake_send)
    monkeypatch.setattr(ss, "_original_create_connection", fake_connect)
    return log


# ── ScanScope.allows ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("host,ok", [
    ("app.example.org", True),
    ("APP.example.org.", True),
    ("x.app.example.org", False),
    ("example.com", True),
    ("a.b.example.com", True),
    ("evilexample.com", False),
    ("example.com.evil.net", False),
    ("93.184.216.34", True),
    ("[2001:db8::1]", True),
    ("10.0.0.1", False),
    ("", False),
    (None, False),
])
def test_allows(host, ok):
    scope = _scope(hosts={"app.example.org"}, suffixes={"example.com"}, ips={"93.184.216.34", "2001:db8::1"})
    assert scope.allows(host) is ok


def test_record_block_dedupes_and_caps():
    scope = _scope()
    for i in range(300):
        scope.record_block(f"h{i % 150}:80")
    assert len(scope.blocked) == ss._MAX_RECORDED
    assert len(set(scope.blocked)) == len(scope.blocked)


# ── Guard on requests ────────────────────────────────────────────────────────

def test_guard_is_installed_by_app_import():
    assert ss.scope_guard_installed()


def test_requests_pass_through_without_scope(fake_net):
    assert requests.get("http://anything.test/") .status_code == 200
    assert fake_net["send"] == ["http://anything.test/"]


def test_requests_in_scope_allowed(fake_net):
    with ss.scan_scope(_scope(hosts={"in.test"})):
        assert requests.get("http://in.test/page").status_code == 200
    assert fake_net["send"] == ["http://in.test/page"]


def test_requests_out_of_scope_blocked(fake_net):
    scope = _scope(hosts={"in.test"})
    with ss.scan_scope(scope):
        with pytest.raises(ss.ScopeViolationError):
            requests.get("http://evil.test/x")
    assert fake_net["send"] == []
    assert scope.blocked == ["http://evil.test/x"]


def test_scope_violation_is_a_connection_error():
    """Scanners already handle these as "couldn't connect"."""
    assert issubclass(ss.ScopeViolationError, requests.exceptions.ConnectionError)
    assert issubclass(ss.ScopeViolationError, OSError)


def test_redirect_off_scope_is_blocked_mid_follow(fake_net):
    scope = _scope(hosts={"in.test"})
    with ss.scan_scope(scope):
        with pytest.raises(ss.ScopeViolationError):
            requests.Session().get("http://in.test/redirect-out", allow_redirects=True)
    assert fake_net["send"] == ["http://in.test/redirect-out"]
    assert scope.blocked == ["http://evil.test/landing"]


def test_redirect_within_scope_is_followed(fake_net):
    with ss.scan_scope(_scope(hosts={"in.test"})):
        r = requests.Session().get("http://in.test/redirect-in", allow_redirects=True)
    assert r.status_code == 200
    assert fake_net["send"] == ["http://in.test/redirect-in", "http://in.test/landing"]


def test_scope_is_reset_after_block(fake_net):
    with ss.scan_scope(_scope(hosts={"in.test"})):
        pass
    assert ss.current_scope() is None
    requests.get("http://evil.test/")
    assert fake_net["send"] == ["http://evil.test/"]


# ── Guard on raw sockets / http.client ───────────────────────────────────────

def test_create_connection_in_and_out_of_scope(fake_net):
    scope = _scope(hosts={"in.test"}, ips={"203.0.113.5"})
    with ss.scan_scope(scope):
        socket.create_connection(("in.test", 443))
        socket.create_connection(("203.0.113.5", 22))
        with pytest.raises(ss.ScopeViolationError):
            socket.create_connection(("evil.test", 443))
    assert fake_net["connect"] == ["in.test:443", "203.0.113.5:22"]
    assert scope.blocked == ["evil.test:443"]


def test_http_client_connection_blocked(fake_net):
    """http.client binds socket.create_connection at construction -- the
    subdomain HEAD probe's path."""
    scope = _scope(hosts={"in.test"})
    with ss.scan_scope(scope):
        conn = http.client.HTTPConnection("evil.test", 80, timeout=1)
        with pytest.raises(ss.ScopeViolationError):
            conn.request("HEAD", "/")
    assert scope.blocked == ["evil.test:80"]
    assert fake_net["connect"] == []


# ── Context propagation ──────────────────────────────────────────────────────

def test_scoped_executor_carries_scope_into_workers():
    scope = _scope(hosts={"in.test"})
    with ss.scan_scope(scope):
        with ss.ScopedThreadPoolExecutor(max_workers=4) as ex:
            seen = list(ex.map(lambda _: ss.current_scope(), range(8)))
    assert all(s is scope for s in seen)


def test_plain_executor_would_lose_the_scope():
    """Why the scanner modules switched executors."""
    with ss.scan_scope(_scope(hosts={"in.test"})):
        with ThreadPoolExecutor(max_workers=2) as ex:
            seen = list(ex.map(lambda _: ss.current_scope(), range(4)))
    assert seen == [None] * 4


def test_run_in_scope_via_to_thread():
    scope = _scope(hosts={"in.test"})

    async def go():
        inner = await asyncio.to_thread(ss.run_in_scope, scope, ss.current_scope)
        return inner, ss.current_scope()
    inner, outer = _run(go())
    assert inner is scope and outer is None


def test_run_in_scope_none_is_unrestricted(fake_net):
    ss.run_in_scope(None, socket.create_connection, ("evil.test", 80))
    assert fake_net["connect"] == ["evil.test:80"]


def test_vuln_concurrency_helper_runs_workers_in_scope(fake_net):
    scope = _scope(hosts={"in.test"})

    def worker(host):
        try:
            requests.get(f"http://{host}/")
            return [host]
        except ss.ScopeViolationError:
            return []

    with ss.scan_scope(scope):
        got = run_concurrent_scan(["in.test", "evil.test", "evil2.test"], worker)
    assert got == ["in.test"]
    assert sorted(scope.blocked) == ["http://evil.test/", "http://evil2.test/"]


# ── Real scanner modules under a scope ───────────────────────────────────────

def test_port_scanner_confined_to_scope(fake_net, monkeypatch):
    monkeypatch.setattr(port_scanner.socket, "gethostbyname", lambda h: "203.0.113.7")
    scope = _scope(hosts={"in.test"})
    with ss.scan_scope(scope):
        out = port_scanner.scan_ports("evil.test", ports=[22, 80, 443])
    assert out["open_count"] == 0
    assert fake_net["connect"] == []
    assert sorted(scope.blocked) == ["evil.test:22", "evil.test:443", "evil.test:80"]

    with ss.scan_scope(_scope(hosts={"in.test"})):
        out = port_scanner.scan_ports("in.test", ports=[22, 80])
    assert out["open_count"] == 2


def test_subdomain_probes_blocked_outside_scope(fake_net, monkeypatch, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("www\n")
    monkeypatch.setattr(subs_mod, "WORDLIST_PATH", wl)
    monkeypatch.setattr(subs_mod, "_resolve", lambda sub: "203.0.113.9")
    scope = _scope(hosts={"example.test"})  # exact host: subdomains not covered
    with ss.scan_scope(scope):
        out = subs_mod.enumerate_subdomains("example.test")
    assert out["mode"] == "active"
    assert out["subdomains"] == []
    assert out["unconfirmed"][0]["reason"] == "probe_failed"
    assert set(scope.blocked) == {"www.example.test:443", "www.example.test:80"}
    assert fake_net["connect"] == []


def test_subdomain_passive_mode_never_probes(monkeypatch, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("www\napi\n")
    monkeypatch.setattr(subs_mod, "WORDLIST_PATH", wl)
    monkeypatch.setattr(subs_mod, "_resolve", lambda sub: "203.0.113.9" if sub.startswith("www") else None)

    def boom(host):
        raise AssertionError("passive mode must not probe hosts")
    monkeypatch.setattr(subs_mod, "_verify_live_host", boom)
    out = subs_mod.enumerate_subdomains("example.test", passive=True)
    assert out == {
        "subdomains": [],
        "unconfirmed": [{"subdomain": "www.example.test", "ip": "203.0.113.9", "reason": "dns_only"}],
        "mode": "passive",
    }


# ── Building scopes from decisions ───────────────────────────────────────────

@pytest.mark.parametrize("basis,expected", [
    ("verified:dns_txt:example.com", (frozenset(), frozenset({"example.com"}))),
    # Anything other than a dns_txt verification, a training target or
    # passive_only gets an empty scope (nothing reachable), not None.
    ("verified:http_file:app.example.org", (frozenset(), frozenset())),
    ("training:scanme.nmap.org", (frozenset({"scanme.nmap.org"}), frozenset())),
    ("passive_only", None),
    ("unenforced:passive_only", (frozenset(), frozenset())),
    ("unenforced:verified:dns_txt:example.com", (frozenset(), frozenset())),
])
def test_scope_targets(basis, expected):
    assert scope_targets(AuthzDecision(basis=basis)) == expected


def test_build_scope_resolves_only_in_scope_names(monkeypatch):
    resolved = []

    def fake_resolve(name):
        resolved.append(name)
        return {"198.51.100.1"} if name == "example.com" else {"198.51.100.2"}
    monkeypatch.setattr(ss, "_resolve", fake_resolve)
    scope = ss.build_scope(suffixes=["Example.com."], resolve=["shop.example.com", "evil.test"])
    assert scope.suffixes == {"example.com"}
    assert sorted(resolved) == ["example.com", "shop.example.com"]
    assert scope.ips == {"198.51.100.1", "198.51.100.2"}


def test_network_scope_for(monkeypatch):
    monkeypatch.setattr(ss, "_resolve", lambda name: {"198.51.100.1"})
    assert _run(dv.network_scope_for(AuthzDecision(basis="passive_only"), "x.test")) is None
    locked = _run(dv.network_scope_for(AuthzDecision(basis="unenforced:passive_only"), "x.test"))
    assert locked is not None and not locked.allows("x.test")
    scope = _run(dv.network_scope_for(AuthzDecision(basis="verified:dns_txt:example.com"), "https://shop.example.com/a"))
    assert scope.suffixes == {"example.com"} and scope.hosts == frozenset()
    assert scope.ips == {"198.51.100.1"}


# ── _run_scan_task wiring ────────────────────────────────────────────────────

def _scan_env(monkeypatch, scan_id):
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    sf = async_sessionmaker(engine, expire_on_commit=False)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with sf() as db:
            db.add(Scan(id=scan_id, user_id=1, target_url="in.test", scan_types=["ports"], status="pending"))
            await db.commit()
    _run(setup())
    monkeypatch.setattr(app_module, "SessionLocal", sf)

    async def no_broadcast(*a, **k):
        return None
    monkeypatch.setattr(app_module.ws_manager, "broadcast", no_broadcast)

    async def no_triage(vulns):
        return [], {"deferred_tpd": 0}
    monkeypatch.setattr(app_module, "classify_findings_batch", no_triage)
    return engine, sf


def _fake_port_step(monkeypatch):
    """A 'ports' step that, like a real scanner following a CNAME/redirect,
    tries one in-scope and one out-of-scope connection."""
    def fake_scan_ports(domain):
        for host in (domain, "evil.test"):
            try:
                socket.create_connection((host, 80))
            except ss.ScopeViolationError:
                pass
        return {"open_ports": []}
    monkeypatch.setattr(port_scanner, "scan_ports", fake_scan_ports)


def _results(engine, sf, scan_id):
    async def go():
        async with sf() as db:
            return (await db.get(Scan, scan_id)).results
    try:
        return _run(go())
    finally:
        _run(engine.dispose())


def test_run_scan_task_runs_active_steps_in_scope_and_reports_blocks(fake_net, monkeypatch):
    engine, sf = _scan_env(monkeypatch, "scope-1")
    _fake_port_step(monkeypatch)
    _run(app_module._run_scan_task(
        "scope-1", "in.test", ["ports"], 1, None,
        authorized_checks={"ports"}, scope=_scope(hosts={"in.test"}),
    ))
    results = _results(engine, sf, "scope-1")
    assert results["scope_blocked"] == ["evil.test:80"]
    assert fake_net["connect"] == ["in.test:80"]


def test_run_scan_task_without_scope_is_unrestricted(fake_net, monkeypatch):
    engine, sf = _scan_env(monkeypatch, "scope-2")
    _fake_port_step(monkeypatch)
    _run(app_module._run_scan_task(
        "scope-2", "in.test", ["ports"], 1, None, authorized_checks={"ports"}, scope=None,
    ))
    results = _results(engine, sf, "scope-2")
    assert "scope_blocked" not in results
    assert fake_net["connect"] == ["in.test:80", "evil.test:80"]
