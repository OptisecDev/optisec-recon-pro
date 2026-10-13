"""
Tests for modules/ai_middleware.py, the asynchronous, sampled AI intent layer.

No real AI provider is ever contacted: every test uses FakeProvider, or a
GroqProvider whose groq.AsyncGroq is monkeypatched to an in-process stub.
The SQL sink test uses a throwaway in-memory sqlite engine, never the app DB.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import modules.ai_middleware as aim
from modules.ai_middleware import (
    AIBlockedLog,
    AnalysisQueue,
    FakeProvider,
    GroqProvider,
    MemoryAuditSink,
    SamplingPolicy,
    SqlAuditSink,
    analyze_intent,
    redact,
)


def run(coro):
    return asyncio.run(coro)


# ── analyze_intent ───────────────────────────────────────────────────────────

def test_malicious_verdict():
    p = FakeProvider({"is_malicious": True, "type": "sqli", "confidence": 0.97})
    assert run(analyze_intent("' OR 1=1 --", p)) == {
        "is_malicious": True, "type": "sqli", "confidence": 0.97,
    }


def test_benign_verdict():
    p = FakeProvider({"is_malicious": False, "type": "benign", "confidence": 0.88})
    assert run(analyze_intent("GET /index.html", p)) == {
        "is_malicious": False, "type": "benign", "confidence": 0.88,
    }


def test_extra_provider_keys_are_dropped_and_int_confidence_accepted():
    p = FakeProvider({"is_malicious": True, "type": "xss", "confidence": 1, "reason": "x"})
    assert run(analyze_intent("<script>", p)) == {"is_malicious": True, "type": "xss", "confidence": 1.0}


@pytest.mark.parametrize("bad", [
    "not a dict",
    ["is_malicious", True],
    {},
    {"is_malicious": "yes", "type": "sqli", "confidence": 0.9},
    {"is_malicious": 1, "type": "sqli", "confidence": 0.9},
    {"is_malicious": True, "type": "", "confidence": 0.9},
    {"is_malicious": True, "type": 42, "confidence": 0.9},
    {"is_malicious": True, "type": "sqli", "confidence": "0.9"},
    {"is_malicious": True, "type": "sqli", "confidence": True},
    {"is_malicious": True, "type": "sqli", "confidence": 1.5},
    {"is_malicious": True, "type": "sqli", "confidence": -0.1},
    {"is_malicious": True, "type": "sqli", "confidence": float("nan")},
    {"is_malicious": True, "type": "sqli"},
])
def test_malformed_provider_output_returns_safe_fallback(bad):
    result = run(analyze_intent("payload", FakeProvider(bad)))
    assert result["is_malicious"] is False
    assert result["type"] == "unknown"
    assert result["confidence"] == 0.0
    assert result["error"].startswith("malformed_output")


def test_provider_exception_returns_fallback_and_does_not_raise():
    p = FakeProvider(exc=RuntimeError("boom secret-detail"))
    result = run(analyze_intent("payload", p))
    assert result == {
        "is_malicious": False, "type": "unknown", "confidence": 0.0,
        "error": "provider_error: RuntimeError",
    }
    # the exception message is never echoed back
    assert "secret-detail" not in result["error"]


def test_provider_timeout_returns_fallback():
    p = FakeProvider(delay=1.0)
    result = run(analyze_intent("payload", p, timeout=0.01))
    assert result["error"] == "provider_timeout"
    assert result["is_malicious"] is False


def test_payload_is_redacted_before_provider_sees_it():
    p = FakeProvider()
    run(analyze_intent("login password=hunter2 from 10.1.2.3 by bob@example.com", p))
    sent = p.calls[0]
    assert "hunter2" not in sent
    assert "10.1.2.3" not in sent
    assert "bob@example.com" not in sent


def test_payload_is_truncated_before_provider_call():
    p = FakeProvider()
    run(analyze_intent("A" * (aim.MAX_PAYLOAD_CHARS * 3), p))
    assert len(p.calls[0]) <= aim.MAX_PAYLOAD_CHARS


# ── GroqProvider (no network) ────────────────────────────────────────────────

def test_groq_provider_without_key_falls_back(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    result = run(analyze_intent("x", GroqProvider(model="test-model")))
    assert result["error"] == "provider_error: RuntimeError"


def test_groq_provider_reads_key_from_env_by_name(monkeypatch):
    import groq

    captured = {}

    class _Msg:
        content = '{"is_malicious": true, "type": "sqli", "confidence": 0.8}'

    class _Choice:
        message = _Msg()

    class _Completion:
        choices = [_Choice()]

    class _Completions:
        async def create(self, **kwargs):
            captured["kwargs"] = kwargs
            return _Completion()

    class _FakeAsyncGroq:
        def __init__(self, api_key, **kwargs):
            captured["api_key"] = api_key
            self.chat = type("C", (), {"completions": _Completions()})()

    monkeypatch.setattr(groq, "AsyncGroq", _FakeAsyncGroq)
    monkeypatch.setenv("GROQ_API_KEY", "test-placeholder-not-a-key")

    result = run(analyze_intent("id=1' or '1'='1", GroqProvider(model="test-model")))
    assert result == {"is_malicious": True, "type": "sqli", "confidence": 0.8}
    assert captured["api_key"] == "test-placeholder-not-a-key"
    assert captured["kwargs"]["model"] == "test-model"


# ── Redaction ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw, secret, label", [
    ("Authorization: Bearer abcDEF123456.xyz-_~", "abcDEF123456.xyz-_~", "[REDACTED_TOKEN]"),
    ("authorization: basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA==", "[REDACTED_TOKEN]"),
    ("Cookie: session=abc123; theme=dark", "abc123", "[REDACTED_COOKIE]"),
    ("Set-Cookie: sid=zzz999; HttpOnly", "zzz999", "[REDACTED_COOKIE]"),
    ('{"cookie": "sid=qq11"}', "qq11", "[REDACTED_COOKIE]"),
    ("user=bob&password=hunter2&x=1", "hunter2", "[REDACTED_SECRET]"),
    ("passwd: s3cr3t!", "s3cr3t!", "[REDACTED_SECRET]"),
    ('{"user": "bob", "password": "p@ss w0rd"}', "p@ss w0rd", "[REDACTED_SECRET]"),
    ("csrf_token=deadbeefcafe", "deadbeefcafe", "[REDACTED_SECRET]"),
    ("?access_token=tok_123456789", "tok_123456789", "[REDACTED_SECRET]"),
    ("api_key=abcdef0123456789", "abcdef0123456789", "[REDACTED_SECRET]"),
    ("X-API-Key: k-1234567890", "k-1234567890", "[REDACTED_SECRET]"),
    ("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlMTIz here",
     "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlMTIz", "[REDACTED_TOKEN]"),
    ("key gsk_" + "A1b2C3d4E5f6G7h8I9j0K1", "gsk_A1b2C3d4E5f6G7h8I9j0K1", "[REDACTED_KEY]"),
    ("key sk-" + "proj-" + "abcdefghijklmnop1234", "abcdefghijklmnop1234", "[REDACTED_KEY]"),
    ("aws AKIA" + "ABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP", "[REDACTED_KEY]"),
    ("gh ghp_" + "a" * 36, "ghp_" + "a" * 36, "[REDACTED_KEY]"),
    ("contact alice.smith+x@corp.example.org now", "alice.smith+x@corp.example.org", "[REDACTED_EMAIL]"),
    ("src 192.168.10.254 dst 8.8.8.8", "192.168.10.254", "[REDACTED_IP]"),
])
def test_redaction_masks_sensitive_values(raw, secret, label):
    out = redact(raw)
    assert secret not in out
    assert label in out


def test_redaction_masks_every_ipv4_and_keeps_non_ips():
    out = redact("a 1.2.3.4 b 255.255.255.255 c version 1.2.3 d 999.1.1.1")
    assert "1.2.3.4" not in out and "255.255.255.255" not in out
    assert "version 1.2.3" in out          # not a full dotted quad
    assert "999.1.1.1" in out              # not a valid IPv4


def test_redaction_keeps_attack_shape_visible():
    out = redact("GET /item?id=1' UNION SELECT username, password FROM users--")
    assert "UNION SELECT" in out
    assert "FROM users" in out


def test_redaction_handles_empty_and_none():
    assert redact("") == ""
    assert redact(None) == ""


def test_redaction_multiline_headers():
    raw = "Host: example.com\nCookie: a=b; c=d\nAuthorization: Bearer zzzzzzzzzz\nUser-Agent: sqlmap"
    out = redact(raw)
    assert "a=b" not in out and "zzzzzzzzzz" not in out
    assert "Host: example.com" in out and "User-Agent: sqlmap" in out


# ── Sampling policy ──────────────────────────────────────────────────────────

def test_default_sampling_rate_is_zero(monkeypatch):
    monkeypatch.delenv("AI_MIDDLEWARE_SAMPLE_RATE", raising=False)
    policy = SamplingPolicy.from_env()
    assert policy.rate == 0.0
    assert not policy.enabled
    assert SamplingPolicy().rate == 0.0
    assert not policy.should_sample({"action": "BLOCK"}, rng=lambda: 0.0)


@pytest.mark.parametrize("value, expected", [
    ("0.25", 0.25), ("1", 1.0), ("5", 1.0), ("-1", 0.0), ("abc", 0.0), ("", 0.0), ("nan", 0.0), ("inf", 0.0),
])
def test_sampling_rate_env_parsing(monkeypatch, value, expected):
    monkeypatch.setenv("AI_MIDDLEWARE_SAMPLE_RATE", value)
    assert SamplingPolicy.from_env().rate == expected


@pytest.mark.parametrize("result, eligible", [
    ({"action": "BLOCK"}, True),
    ({"action": "ALERT"}, True),
    ({"action": "block"}, True),      # ai_firewall uses lower case
    ({"action": "alert"}, True),
    ({"action": "ALLOW"}, False),
    ({"action": "allow"}, False),
    ({}, False),
    ({"action": None}, False),
    (None, False),
    ("BLOCK", False),
])
def test_only_rule_engine_anomalies_are_eligible(result, eligible):
    assert SamplingPolicy.is_eligible(result) is eligible


def test_sampling_fraction_respected():
    policy = SamplingPolicy(rate=0.3)
    assert policy.should_sample({"action": "ALERT"}, rng=lambda: 0.29)
    assert not policy.should_sample({"action": "ALERT"}, rng=lambda: 0.31)
    assert not policy.should_sample({"action": "ALLOW"}, rng=lambda: 0.0)


# ── Queue ────────────────────────────────────────────────────────────────────

def test_queue_processes_sampled_job_and_writes_flagged_audit_record():
    async def scenario():
        provider = FakeProvider({"is_malicious": True, "type": "sqli", "confidence": 0.9})
        sink = MemoryAuditSink()
        q = AnalysisQueue(provider, sink, policy=SamplingPolicy(rate=1.0))
        q.start()
        dpi = {"action": "BLOCK", "threat_score": 85.0, "blocked": True}
        assert q.submit("id=1' OR 1=1 password=hunter2", dpi, dpi_engine="ngfw_v2", user_id=7) is True
        await q.drain()
        await q.stop()
        return sink.records, dpi

    records, dpi = run(scenario())
    assert len(records) == 1
    rec = records[0]
    assert rec["action"] == "flagged"
    assert rec["is_malicious"] is True and rec["verdict_type"] == "sqli"
    assert rec["dpi_action"] == "BLOCK" and rec["dpi_score"] == 85.0
    assert rec["dpi_engine"] == "ngfw_v2" and rec["user_id"] == 7
    assert "hunter2" not in rec["payload_excerpt"]
    assert len(rec["payload_sha256"]) == 64
    # the caller's DPI decision is untouched
    assert dpi == {"action": "BLOCK", "threat_score": 85.0, "blocked": True}


def test_queue_never_calls_provider_when_rate_is_zero():
    async def scenario():
        provider = FakeProvider()
        q = AnalysisQueue(provider, MemoryAuditSink(), policy=SamplingPolicy(rate=0.0))
        q.start()
        accepted = q.submit("x", {"action": "BLOCK"})
        await q.drain()
        await q.stop()
        return accepted, provider.calls

    accepted, calls = run(scenario())
    assert accepted is False
    assert calls == []


def test_queue_skips_non_anomalous_results():
    async def scenario():
        provider = FakeProvider()
        q = AnalysisQueue(provider, MemoryAuditSink(), policy=SamplingPolicy(rate=1.0))
        return q.submit("x", {"action": "ALLOW"}), provider.calls

    accepted, calls = run(scenario())
    assert accepted is False and calls == []


def test_queue_full_drops_without_blocking_or_raising():
    async def scenario():
        q = AnalysisQueue(FakeProvider(), MemoryAuditSink(), policy=SamplingPolicy(rate=1.0), maxsize=1)
        # workers not started, so the queue fills
        first = q.submit("a", {"action": "BLOCK"})
        second = q.submit("b", {"action": "BLOCK"})
        return first, second, q.dropped

    assert run(scenario()) == (True, False, 1)


def test_submit_never_raises_on_garbage_input():
    async def scenario():
        q = AnalysisQueue(FakeProvider(), MemoryAuditSink(), policy=SamplingPolicy(rate=1.0))
        return [q.submit(None, None), q.submit(123, "BLOCK"), q.submit("x", {"action": object()})]

    assert run(scenario()) == [False, False, False]


def test_queue_survives_provider_and_sink_failures():
    async def scenario():
        async def broken_sink(_record):
            raise RuntimeError("db down")

        q = AnalysisQueue(FakeProvider(exc=ValueError("x")), broken_sink, policy=SamplingPolicy(rate=1.0))
        q.start()
        q.submit("a", {"action": "ALERT"})
        q.submit("b", {"action": "ALERT"})
        await asyncio.wait_for(q.drain(), timeout=2)
        alive = all(not t.done() for t in q._tasks)
        await q.stop()
        return alive

    assert run(scenario()) is True


def test_submit_returns_only_bool_not_verdict():
    """The request path gets nothing from the AI layer that could alter its decision."""
    async def scenario():
        q = AnalysisQueue(FakeProvider({"is_malicious": True, "type": "sqli", "confidence": 1.0}),
                          MemoryAuditSink(), policy=SamplingPolicy(rate=1.0))
        return q.submit("x", {"action": "ALERT"})

    assert run(scenario()) is True


# ── Storage ──────────────────────────────────────────────────────────────────

def test_audit_table_not_registered_on_app_metadata():
    """init_db() runs create_all on web.database.Base; the AI table must not be on it."""
    from web.database import Base
    assert AIBlockedLog.__tablename__ not in Base.metadata.tables


def test_sql_sink_writes_flagged_row_to_throwaway_sqlite():
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    async def scenario():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(aim.AuditBase.metadata.create_all)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        sink = SqlAuditSink(factory)
        record = aim.build_audit_record(
            "x", {"is_malicious": True, "type": "xss", "confidence": 0.7}, {"action": "ALERT"}, "fake",
        )
        record["action"] = "block"   # a caller trying to smuggle a block is overridden
        await sink(record)
        async with factory() as s:
            rows = (await s.execute(select(AIBlockedLog))).scalars().all()
        await engine.dispose()
        return rows

    rows = run(scenario())
    assert len(rows) == 1
    assert rows[0].action == "flagged"
    assert rows[0].verdict_type == "xss"


def test_audit_table_check_constraint_rejects_non_flagged_action():
    from sqlalchemy import insert
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.ext.asyncio import create_async_engine

    async def scenario():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(aim.AuditBase.metadata.create_all)
        try:
            async with engine.begin() as conn:
                await conn.execute(insert(AIBlockedLog.__table__).values(
                    action="block", provider="fake", payload_sha256="0" * 64,
                ))
            return False
        except IntegrityError:
            return True
        finally:
            await engine.dispose()

    assert run(scenario()) is True


# ── Isolation from the DPI engines ───────────────────────────────────────────

def test_dpi_engines_do_not_import_ai_middleware():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for rel in ("modules/firewall/ngfw_v2.py", "modules/firewall/ai_firewall.py",
                "web/routers/ngfw.py", "web/routers/firewall.py"):
        with open(os.path.join(root, rel), encoding="utf-8") as fh:
            assert "ai_middleware" not in fh.read(), rel
