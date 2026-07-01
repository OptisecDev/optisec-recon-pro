"""
Tests for the Honeypot module: lightweight SSH/FTP/HTTP-admin decoy
listeners (modules/honeypot/listeners.py), attacker IP enrichment
(modules/honeypot/enrichment.py), lifecycle + persistence
(modules/honeypot/manager.py) and the query/aggregation router
(web/routers/honeypot.py).

Mirrors tests/test_darkweb_scheduler.py's conventions: plain pytest, async
functions driven via asyncio.run(), monkeypatch for isolation, and an
in-memory SQLite engine wired in place of web.database.SessionLocal so no
test touches the real project database. The listener tests are real
integration tests over 127.0.0.1 on OS-assigned (port 0) sockets — no
external network access and no privileged ports are ever used.
"""

import asyncio
import contextlib
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

import web.database as database
from web.database import Base
from web.models import HoneypotEvent
import modules.honeypot.listeners as listeners
import modules.honeypot.enrichment as enrichment
import modules.honeypot.manager as manager
import web.routers.honeypot as hp_router


def _run(coro):
    return asyncio.run(coro)


# ── Isolated in-memory DB fixture (same pattern as test_darkweb_scheduler.py) ─

@pytest.fixture
def db(monkeypatch):
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    TestSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    _run(_setup())
    monkeypatch.setattr(database, "SessionLocal", TestSessionLocal)
    yield TestSessionLocal
    _run(engine.dispose())


async def _seed_event(session_factory, **overrides) -> int:
    defaults = dict(
        service="ssh", source_ip="1.1.1.1", source_port=1234, dest_port=2222,
        payload="x", session_data={}, country=None, country_code=None, city=None, isp=None,
        abuse_score=0, risk_level="LOW", enrichment={}, created_at=datetime.utcnow(),
    )
    defaults.update(overrides)
    async with session_factory() as db_:
        row = HoneypotEvent(**defaults)
        db_.add(row)
        await db_.commit()
        await db_.refresh(row)
        return row.id


@pytest.fixture(autouse=True)
def _reset_manager_state():
    """Every test starts and ends with no live honeypot listeners, so tests
    can't leak bound sockets/state into each other."""
    manager._servers.clear()
    yield
    _run(manager.stop_honeypots())
    manager._servers.clear()


# ── 1. Protocol parsing (pure functions) ─────────────────────────────────

class TestParseFtpCommand:
    def test_parses_command_and_argument(self):
        assert listeners.parse_ftp_command("USER admin\r\n") == {"command": "USER", "arg": "admin"}

    def test_uppercases_command(self):
        assert listeners.parse_ftp_command("user admin") == {"command": "USER", "arg": "admin"}

    def test_command_without_argument(self):
        assert listeners.parse_ftp_command("QUIT\r\n") == {"command": "QUIT", "arg": ""}

    def test_empty_line_yields_empty_command(self):
        assert listeners.parse_ftp_command("\r\n") == {"command": "", "arg": ""}


class TestParseHttpRequest:
    def test_parses_method_path_headers_body(self):
        raw = b"POST /wp-admin/admin-ajax.php HTTP/1.1\r\nHost: x\r\nUser-Agent: sqlmap\r\nContent-Length: 13\r\n\r\nuser=root&pw=1"
        parsed = listeners.parse_http_request(raw)
        assert parsed["method"] == "POST"
        assert parsed["path"] == "/wp-admin/admin-ajax.php"
        assert parsed["headers"]["user-agent"] == "sqlmap"
        assert parsed["headers"]["host"] == "x"
        assert parsed["body"] == "user=root&pw=1"

    def test_get_request_without_body(self):
        raw = b"GET /admin HTTP/1.1\r\nHost: x\r\n\r\n"
        parsed = listeners.parse_http_request(raw)
        assert parsed["method"] == "GET"
        assert parsed["path"] == "/admin"
        assert parsed["body"] == ""

    def test_malformed_bytes_never_raises(self):
        parsed = listeners.parse_http_request(b"\xff\xfe\x00garbage not http at all")
        assert set(parsed) == {"method", "path", "headers", "body"}
        assert isinstance(parsed["headers"], dict)

    def test_empty_bytes(self):
        parsed = listeners.parse_http_request(b"")
        assert parsed["method"] == ""
        assert parsed["path"] == ""
        assert parsed["headers"] == {}
        assert parsed["body"] == ""


# ── 2. Live listener integration tests (real loopback sockets, port 0) ──────

async def _start(service: str, on_event):
    return await listeners.start_listener(service, "127.0.0.1", 0, on_event)


async def _stop(server):
    server.close()
    await server.wait_closed()


def _event_collector():
    events: list[dict] = []
    done = asyncio.Event()

    async def on_event(e):
        events.append(e)
        done.set()

    return events, done, on_event


class TestSSHListener:
    def test_sends_banner_and_captures_client_hello(self):
        events, done, on_event = _event_collector()

        async def go():
            server = await _start("ssh", on_event)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                banner = await reader.readuntil(b"\r\n")
                assert banner == listeners.SSH_BANNER
                writer.write(b"SSH-2.0-PuTTY_Release_0.78\r\n")
                await writer.drain()
                await asyncio.wait_for(done.wait(), timeout=3)
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                await _stop(server)

        _run(go())
        assert len(events) == 1
        assert events[0]["service"] == "ssh"
        assert "PuTTY" in events[0]["payload"]
        assert events[0]["session_data"]["banner_sent"] == listeners.SSH_BANNER.decode()

    def test_client_that_sends_nothing_times_out_with_empty_payload(self, monkeypatch):
        monkeypatch.setattr(listeners, "READ_TIMEOUT_SECONDS", 0.2)
        events, done, on_event = _event_collector()

        async def go():
            server = await _start("ssh", on_event)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                await reader.readuntil(b"\r\n")
                await asyncio.wait_for(done.wait(), timeout=3)
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                await _stop(server)

        _run(go())
        assert events[0]["payload"] == ""


class TestFTPListener:
    def test_credential_stuffing_attempt_is_captured(self):
        events, done, on_event = _event_collector()

        async def go():
            server = await _start("ftp", on_event)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                banner = await reader.readuntil(b"\r\n")
                assert banner == listeners.FTP_BANNER

                writer.write(b"USER admin\r\n")
                await writer.drain()
                resp1 = await reader.readuntil(b"\r\n")
                assert b"331" in resp1

                writer.write(b"PASS hunter2\r\n")
                await writer.drain()
                resp2 = await reader.readuntil(b"\r\n")
                assert b"530" in resp2

                writer.write(b"QUIT\r\n")
                await writer.drain()
                await asyncio.wait_for(done.wait(), timeout=3)
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                await _stop(server)

        _run(go())
        assert len(events) == 1
        commands = events[0]["session_data"]["commands"]
        assert commands[0] == {"command": "USER", "arg": "admin"}
        assert commands[1] == {"command": "PASS", "arg": "hunter2"}
        assert "USER admin" in events[0]["payload"]
        assert "hunter2" in events[0]["payload"]

    def test_unknown_command_gets_default_response(self):
        events, done, on_event = _event_collector()

        async def go():
            server = await _start("ftp", on_event)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                await reader.readuntil(b"\r\n")
                writer.write(b"NOOP\r\n")
                await writer.drain()
                resp = await reader.readuntil(b"\r\n")
                assert b"502" in resp
                writer.write(b"QUIT\r\n")
                await writer.drain()
                await asyncio.wait_for(done.wait(), timeout=3)
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                await _stop(server)

        _run(go())
        assert events[0]["session_data"]["commands"][0]["command"] == "NOOP"


class TestHTTPAdminListener:
    def test_serves_fake_login_page_and_logs_request(self):
        events, done, on_event = _event_collector()

        async def go():
            server = await _start("http_admin", on_event)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                req = (
                    b"POST /wp-admin/admin-ajax.php HTTP/1.1\r\n"
                    b"Host: target\r\n"
                    b"User-Agent: sqlmap/1.7\r\n"
                    b"X-Custom-Header: should-be-dropped\r\n"
                    b"Content-Length: 13\r\n\r\n"
                    b"user=root&pw=1"
                )
                writer.write(req)
                await writer.drain()
                raw_resp = await reader.read(-1)
                await asyncio.wait_for(done.wait(), timeout=3)
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                await _stop(server)
            return raw_resp

        raw_resp = _run(go())
        assert b"200 OK" in raw_resp
        assert b"Administration Panel" in raw_resp

        assert len(events) == 1
        ev = events[0]
        assert ev["service"] == "http_admin"
        assert ev["session_data"]["method"] == "POST"
        assert ev["session_data"]["path"] == "/wp-admin/admin-ajax.php"
        assert ev["session_data"]["headers"]["user-agent"] == "sqlmap/1.7"
        assert "x-custom-header" not in ev["session_data"]["headers"]
        assert "user=root&pw=1" in ev["payload"]


class TestOnEventNeverCrashesListener:
    def test_broken_callback_does_not_take_down_the_listener(self):
        async def boom(event):
            raise RuntimeError("callback exploded")

        async def go():
            server = await _start("ssh", boom)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                await reader.readuntil(b"\r\n")
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

            # Listener must still be alive and accept a second connection.
            reader2, writer2 = await asyncio.open_connection("127.0.0.1", port)
            try:
                banner = await reader2.readuntil(b"\r\n")
                assert banner == listeners.SSH_BANNER
            finally:
                writer2.close()
                with contextlib.suppress(Exception):
                    await writer2.wait_closed()
                await _stop(server)

        _run(go())  # must not raise


# ── 3. Enrichment ────────────────────────────────────────────────────────

class _FakeHTTPXResponse:
    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json = json_data or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._json


class _FakeAsyncClient:
    def __init__(self, responder):
        self._responder = responder

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, **kwargs):
        return self._responder(url, kwargs)


def _patch_abuseipdb(monkeypatch, responder):
    monkeypatch.setattr(enrichment.httpx, "AsyncClient", lambda *a, **kw: _FakeAsyncClient(responder))


class TestQueryAbuseIPDB:
    def test_no_key_returns_unavailable(self, monkeypatch):
        monkeypatch.setattr(enrichment, "ABUSEIPDB_KEY", "")
        result = _run(enrichment._query_abuseipdb("1.2.3.4"))
        assert result["available"] is False
        assert result["error"] == "ABUSEIPDB_API_KEY not set"

    def test_success_parses_fields(self, monkeypatch):
        monkeypatch.setattr(enrichment, "ABUSEIPDB_KEY", "testkey")

        def responder(url, kwargs):
            assert kwargs["params"]["ipAddress"] == "1.2.3.4"
            return _FakeHTTPXResponse(200, {"data": {
                "abuseConfidenceScore": 87, "totalReports": 12,
                "isTor": True, "usageType": "Data Center", "domain": "evil.com",
            }})

        _patch_abuseipdb(monkeypatch, responder)
        result = _run(enrichment._query_abuseipdb("1.2.3.4"))
        assert result == {
            "available": True, "score": 87, "total_reports": 12, "is_tor": True,
            "usage_type": "Data Center", "domain": "evil.com", "error": None,
        }

    def test_request_exception_yields_error(self, monkeypatch):
        monkeypatch.setattr(enrichment, "ABUSEIPDB_KEY", "testkey")

        def responder(url, kwargs):
            raise RuntimeError("network down")

        _patch_abuseipdb(monkeypatch, responder)
        result = _run(enrichment._query_abuseipdb("1.2.3.4"))
        assert result["available"] is False
        assert "network down" in result["error"]

    def test_http_error_status_yields_error(self, monkeypatch):
        monkeypatch.setattr(enrichment, "ABUSEIPDB_KEY", "testkey")
        _patch_abuseipdb(monkeypatch, lambda url, kwargs: _FakeHTTPXResponse(401))
        result = _run(enrichment._query_abuseipdb("1.2.3.4"))
        assert result["available"] is False
        assert result["error"] is not None


class TestRiskLevel:
    @pytest.mark.parametrize("abuse,geo,expected", [
        (0, 0, "LOW"), (24, 0, "LOW"),
        (25, 0, "MEDIUM"), (49, 0, "MEDIUM"),
        (50, 0, "HIGH"), (74, 0, "HIGH"),
        (75, 0, "CRITICAL"), (0, 90, "CRITICAL"),
    ])
    def test_thresholds(self, abuse, geo, expected):
        assert enrichment._risk_level(abuse, geo) == expected


class TestEnrichIP:
    def test_combines_geo_and_abuse(self, monkeypatch):
        async def fake_geo(ip):
            return {"country": "Iraq", "country_code": "IQ", "city": "Baghdad",
                     "isp": "Zain", "asn": "AS1", "risk_score": 30}
        monkeypatch.setattr(enrichment, "geolocate_ip", fake_geo)

        async def fake_abuse(ip):
            return {"available": True, "score": 80, "total_reports": 5, "is_tor": False,
                     "usage_type": "isp", "domain": None, "error": None}
        monkeypatch.setattr(enrichment, "_query_abuseipdb", fake_abuse)

        result = _run(enrichment.enrich_ip("9.9.9.9"))
        assert result["country"] == "Iraq"
        assert result["abuse_score"] == 80
        assert result["risk_level"] == "CRITICAL"
        assert result["risk_level_ar"] == "حرج"

    def test_geo_error_degrades_gracefully(self, monkeypatch):
        async def fake_geo(ip):
            return {"error": "resolution failed"}
        monkeypatch.setattr(enrichment, "geolocate_ip", fake_geo)

        async def fake_abuse(ip):
            return {"available": False, "score": 0, "total_reports": 0, "is_tor": False,
                     "usage_type": None, "domain": None, "error": "no key"}
        monkeypatch.setattr(enrichment, "_query_abuseipdb", fake_abuse)

        result = _run(enrichment.enrich_ip("9.9.9.9"))
        assert result["country"] is None
        assert result["risk_level"] == "LOW"

    def test_never_raises_when_both_providers_crash(self, monkeypatch):
        async def boom_geo(ip):
            raise RuntimeError("geo down")

        async def boom_abuse(ip):
            raise RuntimeError("abuse down")

        monkeypatch.setattr(enrichment, "geolocate_ip", boom_geo)
        monkeypatch.setattr(enrichment, "_query_abuseipdb", boom_abuse)
        result = _run(enrichment.enrich_ip("9.9.9.9"))  # must not raise
        assert result["risk_level"] == "LOW"
        assert result["abuse_score"] == 0


# ── 4. Manager — env config ──────────────────────────────────────────────

class TestEnvHelpers:
    def test_bool_env_default_when_unset(self, monkeypatch):
        monkeypatch.delenv("HP_TEST_FLAG", raising=False)
        assert manager._bool_env("HP_TEST_FLAG", True) is True
        assert manager._bool_env("HP_TEST_FLAG", False) is False

    @pytest.mark.parametrize("value", ["1", "true", "True", "yes", "on"])
    def test_bool_env_truthy_values(self, monkeypatch, value):
        monkeypatch.setenv("HP_TEST_FLAG", value)
        assert manager._bool_env("HP_TEST_FLAG", False) is True

    @pytest.mark.parametrize("value", ["0", "false", "no", "off", "garbage"])
    def test_bool_env_falsy_values(self, monkeypatch, value):
        monkeypatch.setenv("HP_TEST_FLAG", value)
        assert manager._bool_env("HP_TEST_FLAG", True) is False

    def test_port_env_default_when_unset(self, monkeypatch):
        monkeypatch.delenv("HP_TEST_PORT", raising=False)
        assert manager._port_env("HP_TEST_PORT", 1234) == 1234

    def test_port_env_custom_value(self, monkeypatch):
        monkeypatch.setenv("HP_TEST_PORT", "9999")
        assert manager._port_env("HP_TEST_PORT", 1234) == 9999

    def test_port_env_invalid_falls_back(self, monkeypatch):
        monkeypatch.setenv("HP_TEST_PORT", "not-a-port")
        assert manager._port_env("HP_TEST_PORT", 1234) == 1234

    def test_port_env_out_of_range_falls_back(self, monkeypatch):
        monkeypatch.setenv("HP_TEST_PORT", "70000")
        assert manager._port_env("HP_TEST_PORT", 1234) == 1234


class TestServiceConfig:
    _ALL_VARS = (
        "HONEYPOT_ENABLED", "HONEYPOT_BIND_HOST",
        "HONEYPOT_SSH_ENABLED", "HONEYPOT_SSH_PORT",
        "HONEYPOT_FTP_ENABLED", "HONEYPOT_FTP_PORT",
        "HONEYPOT_HTTP_ENABLED", "HONEYPOT_HTTP_PORT",
    )

    @pytest.fixture(autouse=True)
    def _clear_env(self, monkeypatch):
        for var in self._ALL_VARS:
            monkeypatch.delenv(var, raising=False)

    def test_disabled_by_default(self):
        assert manager.is_enabled() is False

    def test_bind_host_default(self):
        assert manager.get_bind_host() == "0.0.0.0"

    def test_default_ports_are_non_standard(self):
        cfg = manager.service_config()
        assert cfg["ssh"] == {"enabled": True, "port": 2222}
        assert cfg["ftp"] == {"enabled": True, "port": 2121}
        assert cfg["http_admin"] == {"enabled": True, "port": 8081}
        # None of the defaults may collide with a real service's port.
        used_ports = {c["port"] for c in cfg.values()}
        assert used_ports.isdisjoint({22, 21, 80, 443, 8000})

    def test_custom_env_overrides(self, monkeypatch):
        monkeypatch.setenv("HONEYPOT_SSH_PORT", "3333")
        monkeypatch.setenv("HONEYPOT_FTP_ENABLED", "false")
        cfg = manager.service_config()
        assert cfg["ssh"]["port"] == 3333
        assert cfg["ftp"]["enabled"] is False


# ── 5. Manager — record_event persistence ────────────────────────────────

class TestRecordEvent:
    def test_persists_event_with_enrichment(self, db, monkeypatch):
        async def fake_enrich(ip):
            return {"country": "Iraq", "country_code": "IQ", "city": "Baghdad", "isp": "Zain",
                     "abuse_score": 80, "risk_level": "CRITICAL"}
        monkeypatch.setattr("modules.honeypot.enrichment.enrich_ip", fake_enrich)

        event = {"service": "ssh", "source_ip": "1.2.3.4", "source_port": 5555,
                  "payload": "SSH-2.0-test", "session_data": {"x": 1}}
        _run(manager.record_event(event))

        async def fetch():
            async with db() as db_:
                return (await db_.execute(select(HoneypotEvent))).scalars().all()
        rows = _run(fetch())
        assert len(rows) == 1
        row = rows[0]
        assert row.service == "ssh"
        assert row.source_ip == "1.2.3.4"
        assert row.source_port == 5555
        assert row.country == "Iraq"
        assert row.risk_level == "CRITICAL"
        assert row.abuse_score == 80
        assert row.session_data == {"x": 1}

    def test_never_raises_if_enrichment_fails(self, db, monkeypatch):
        async def boom(ip):
            raise RuntimeError("network down")
        monkeypatch.setattr("modules.honeypot.enrichment.enrich_ip", boom)

        _run(manager.record_event({"service": "ftp", "source_ip": "5.6.7.8", "payload": "USER x"}))

        async def fetch():
            async with db() as db_:
                return (await db_.execute(select(HoneypotEvent))).scalars().all()
        rows = _run(fetch())
        assert len(rows) == 1
        assert rows[0].risk_level == "UNKNOWN"

    def test_never_raises_if_db_write_fails(self, monkeypatch):
        async def fake_enrich(ip):
            return {"country": None, "country_code": None, "city": None, "isp": None,
                     "abuse_score": 0, "risk_level": "LOW"}
        monkeypatch.setattr("modules.honeypot.enrichment.enrich_ip", fake_enrich)

        def boom_session():
            raise RuntimeError("db unreachable")
        monkeypatch.setattr(database, "SessionLocal", boom_session)

        _run(manager.record_event({"service": "ssh", "source_ip": "1.1.1.1"}))  # must not raise


# ── 6. Manager — lifecycle (start/stop on ephemeral ports) ──────────────

class TestLifecycle:
    def test_disabled_by_default_does_not_start_listeners(self, monkeypatch):
        monkeypatch.delenv("HONEYPOT_ENABLED", raising=False)
        status = _run(manager.start_honeypots())
        assert status["enabled"] is False
        assert all(not s["listening"] for s in status["services"].values())

    def test_enabled_starts_every_service_on_ephemeral_ports(self, monkeypatch):
        monkeypatch.setenv("HONEYPOT_ENABLED", "true")
        monkeypatch.setenv("HONEYPOT_BIND_HOST", "127.0.0.1")
        monkeypatch.setenv("HONEYPOT_SSH_PORT", "0")
        monkeypatch.setenv("HONEYPOT_FTP_PORT", "0")
        monkeypatch.setenv("HONEYPOT_HTTP_PORT", "0")

        status = _run(manager.start_honeypots())
        assert status["enabled"] is True
        assert all(s["listening"] for s in status["services"].values())

        _run(manager.stop_honeypots())
        status2 = manager.get_status()
        assert all(not s["listening"] for s in status2["services"].values())

    def test_individually_disabled_service_is_not_started(self, monkeypatch):
        monkeypatch.setenv("HONEYPOT_ENABLED", "true")
        monkeypatch.setenv("HONEYPOT_BIND_HOST", "127.0.0.1")
        monkeypatch.setenv("HONEYPOT_SSH_PORT", "0")
        monkeypatch.setenv("HONEYPOT_FTP_ENABLED", "false")
        monkeypatch.setenv("HONEYPOT_HTTP_ENABLED", "false")

        status = _run(manager.start_honeypots())
        assert status["services"]["ssh"]["listening"] is True
        assert status["services"]["ftp"]["listening"] is False
        assert status["services"]["http_admin"]["listening"] is False

    def test_start_is_idempotent_for_already_running_service(self, monkeypatch):
        monkeypatch.setenv("HONEYPOT_ENABLED", "true")
        monkeypatch.setenv("HONEYPOT_BIND_HOST", "127.0.0.1")
        monkeypatch.setenv("HONEYPOT_SSH_PORT", "0")
        monkeypatch.setenv("HONEYPOT_FTP_ENABLED", "false")
        monkeypatch.setenv("HONEYPOT_HTTP_ENABLED", "false")

        _run(manager.start_honeypots())
        server_before = manager._servers["ssh"]
        _run(manager.start_honeypots())
        assert manager._servers["ssh"] is server_before

    def test_stop_before_start_is_safe(self):
        _run(manager.stop_honeypots())  # no-op, must not raise

    def test_get_status_reports_labels_and_ports(self, monkeypatch):
        monkeypatch.delenv("HONEYPOT_ENABLED", raising=False)
        status = manager.get_status()
        assert status["services"]["ssh"]["label_ar"] == listeners.SERVICE_LABELS_AR["ssh"]
        assert status["services"]["ftp"]["port"] == 2121


# ── 7. Router — query/aggregation logic ──────────────────────────────────

@pytest.fixture
def db_factory():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    _run(_setup())
    yield session_factory
    _run(engine.dispose())


class TestEventToDict:
    def test_includes_arabic_service_label_and_iso_timestamp(self):
        e = HoneypotEvent(
            id=1, service="ssh", source_ip="1.2.3.4", source_port=1, dest_port=2222,
            payload="p", session_data={}, country="Iraq", country_code="IQ", city="c", isp="i",
            abuse_score=10, risk_level="LOW", created_at=datetime(2026, 1, 1, 12, 0, 0),
        )
        d = hp_router._event_to_dict(e)
        assert d["service_ar"] == listeners.SERVICE_LABELS_AR["ssh"]
        assert d["created_at"] == "2026-01-01T12:00:00"
        assert d["source_ip"] == "1.2.3.4"


class TestQueryEvents:
    def test_filters_by_service(self, db_factory):
        async def seed():
            await _seed_event(db_factory, service="ssh")
            await _seed_event(db_factory, service="ftp")
        _run(seed())

        async def go():
            async with db_factory() as db_:
                return await hp_router.query_events(db_, service="ftp")
        rows = _run(go())
        assert len(rows) == 1 and rows[0].service == "ftp"

    def test_filters_by_source_ip(self, db_factory):
        async def seed():
            await _seed_event(db_factory, source_ip="1.1.1.1")
            await _seed_event(db_factory, source_ip="2.2.2.2")
        _run(seed())

        async def go():
            async with db_factory() as db_:
                return await hp_router.query_events(db_, source_ip="2.2.2.2")
        rows = _run(go())
        assert len(rows) == 1 and rows[0].source_ip == "2.2.2.2"

    def test_filters_by_risk_level_case_insensitive(self, db_factory):
        async def seed():
            await _seed_event(db_factory, risk_level="CRITICAL")
            await _seed_event(db_factory, risk_level="LOW")
        _run(seed())

        async def go():
            async with db_factory() as db_:
                return await hp_router.query_events(db_, risk_level="critical")
        rows = _run(go())
        assert len(rows) == 1 and rows[0].risk_level == "CRITICAL"

    def test_filters_by_since(self, db_factory):
        async def seed():
            await _seed_event(db_factory, created_at=datetime.utcnow() - timedelta(days=10))
            await _seed_event(db_factory, created_at=datetime.utcnow())
        _run(seed())

        async def go():
            async with db_factory() as db_:
                return await hp_router.query_events(db_, since=datetime.utcnow() - timedelta(days=1))
        rows = _run(go())
        assert len(rows) == 1

    def test_orders_newest_first(self, db_factory):
        async def seed():
            await _seed_event(db_factory, source_ip="old", created_at=datetime.utcnow() - timedelta(hours=2))
            await _seed_event(db_factory, source_ip="new", created_at=datetime.utcnow())
        _run(seed())

        async def go():
            async with db_factory() as db_:
                return await hp_router.query_events(db_)
        rows = _run(go())
        assert [r.source_ip for r in rows] == ["new", "old"]

    def test_limit_is_clamped_between_1_and_200(self, db_factory):
        async def seed():
            for _ in range(3):
                await _seed_event(db_factory)
        _run(seed())

        async def go(limit):
            async with db_factory() as db_:
                return await hp_router.query_events(db_, limit=limit)
        assert len(_run(go(0))) == 1
        assert len(_run(go(9999))) == 3  # clamped to 200, but only 3 rows exist

    def test_offset_floors_at_zero(self, db_factory):
        async def seed():
            await _seed_event(db_factory)
        _run(seed())

        async def go():
            async with db_factory() as db_:
                return await hp_router.query_events(db_, offset=-5)
        assert len(_run(go())) == 1


class TestBuildHeatmap:
    def test_buckets_by_weekday_and_hour(self):
        ts = datetime(2026, 6, 29, 14, 0)
        grid = hp_router.build_heatmap([ts, ts])
        cell = next(c for c in grid if c["weekday"] == ts.weekday() and c["hour"] == 14)
        assert cell["count"] == 2
        assert len(grid) == 7 * 24

    def test_ignores_none_timestamps(self):
        grid = hp_router.build_heatmap([None, None])
        assert all(c["count"] == 0 for c in grid)

    def test_empty_input_still_returns_full_grid(self):
        grid = hp_router.build_heatmap([])
        assert len(grid) == 168
        assert all(c["count"] == 0 for c in grid)


class TestComputeStats:
    def test_aggregates_totals_breakdowns_and_top_lists(self, db_factory):
        async def seed():
            await _seed_event(db_factory, service="ssh", source_ip="1.1.1.1", risk_level="CRITICAL", country="Iraq")
            await _seed_event(db_factory, service="ssh", source_ip="1.1.1.1", risk_level="HIGH", country="Iraq")
            await _seed_event(db_factory, service="ftp", source_ip="2.2.2.2", risk_level="LOW", country="USA")
        _run(seed())

        async def go():
            async with db_factory() as db_:
                return await hp_router.compute_stats(db_)
        stats = _run(go())

        assert stats["total_events"] == 3
        assert stats["by_service"]["ssh"] == 2
        assert stats["by_service"]["ftp"] == 1
        assert stats["by_service_ar"]["ssh"] == listeners.SERVICE_LABELS_AR["ssh"]
        assert stats["by_risk_level"]["CRITICAL"] == 1
        assert stats["top_attacker_ips"][0] == {"ip": "1.1.1.1", "hits": 2}
        assert {c["country"] for c in stats["top_countries"]} == {"Iraq", "USA"}
        assert len(stats["heatmap_7d"]) == 168

    def test_events_older_than_7_days_excluded_from_recent_window(self, db_factory):
        async def seed():
            await _seed_event(db_factory, created_at=datetime.utcnow() - timedelta(days=10))
            await _seed_event(db_factory, created_at=datetime.utcnow())
        _run(seed())

        async def go():
            async with db_factory() as db_:
                return await hp_router.compute_stats(db_)
        stats = _run(go())
        assert stats["total_events"] == 2
        assert stats["events_last_7d"] == 1

    def test_countries_with_none_are_excluded_from_top_countries(self, db_factory):
        async def seed():
            await _seed_event(db_factory, country=None)
        _run(seed())

        async def go():
            async with db_factory() as db_:
                return await hp_router.compute_stats(db_)
        stats = _run(go())
        assert stats["top_countries"] == []

    def test_empty_db_returns_zeroed_stats(self, db_factory):
        async def go():
            async with db_factory() as db_:
                return await hp_router.compute_stats(db_)
        stats = _run(go())
        assert stats["total_events"] == 0
        assert stats["top_attacker_ips"] == []
        assert stats["events_last_7d"] == 0


# ── 8. Arabic localization ────────────────────────────────────────────────

class TestArabicLabels:
    def test_service_labels_cover_all_three_services(self):
        assert set(listeners.SERVICE_LABELS_AR) == {"ssh", "ftp", "http_admin"}
        assert all(isinstance(v, str) and v for v in listeners.SERVICE_LABELS_AR.values())

    def test_risk_labels_cover_every_level(self):
        assert set(enrichment.RISK_LEVELS_AR) == {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}
        assert all(isinstance(v, str) and v for v in enrichment.RISK_LEVELS_AR.values())
