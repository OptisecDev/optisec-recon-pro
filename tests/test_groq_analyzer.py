"""
Tests for the "AI Analysis" fix in modules/ai/groq_analyzer.py::analyze_findings
(the function behind POST /api/ai/analyze), covering:

- the condensed findings summary (max 5 shown, remainder as a count)
- the non-AI generate_static_summary() fallback
- the in-memory cache keyed on (findings, target, lang)
- the daily token budget preflight check
- retry_on skipping retries for a daily (TPD) rate-limit error specifically

No real Groq API call is made anywhere in this file: modules.ai.groq_analyzer._client
is monkeypatched to a fake client whose chat.completions.create is a plain
Python stub. time.sleep is stubbed so retry backoff doesn't actually wait.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import modules.ai.groq_analyzer as groq_analyzer
import modules.ai.rate_limiter as rate_limiter


@pytest.fixture(autouse=True)
def _isolate_global_state(monkeypatch):
    """Every test gets a clean cache and a fresh default daily budget."""
    groq_analyzer._analysis_cache.clear()
    rate_limiter._default_daily_budget = None
    monkeypatch.setattr("modules.ai.groq_client_utils.time.sleep", lambda _seconds: None)
    yield
    groq_analyzer._analysis_cache.clear()
    rate_limiter._default_daily_budget = None


def _findings(n, base_type="xss"):
    return [
        {"type": f"{base_type}-{i}", "severity": "High" if i % 2 == 0 else "Medium", "parameter": f"param{i}"}
        for i in range(n)
    ]


class _FakeResponse:
    def __init__(self, content):
        self.choices = [type("Choice", (), {"message": type("Msg", (), {"content": content})()})()]


class _FakeGroqRateLimitError(Exception):
    """Duck-types groq.RateLimitError's shape for a genuine TPD (daily) 429."""

    def __init__(self):
        message = (
            "Rate limit reached for model `openai/gpt-oss-120b` on tokens "
            "per day (TPD): Limit 200000, Used 200000, Requested 500. "
            "Please try again in 300s."
        )
        self.status_code = 429
        self.body = {"error": {"message": message, "type": "tokens", "code": "rate_limit_exceeded"}}
        self.response = type("Resp", (), {"headers": {"retry-after": "300"}})()


# ── _build_findings_summary ────────────────────────────────────────────────


def test_build_findings_summary_shows_all_when_five_or_fewer():
    summary = groq_analyzer._build_findings_summary(_findings(3), lang="ar")
    assert summary.count("\n") == 2  # 3 lines, no remainder line
    assert "إضافية" not in summary


def test_build_findings_summary_caps_at_five_and_counts_remainder_ar():
    summary = groq_analyzer._build_findings_summary(_findings(8), lang="ar")
    shown_lines = [l for l in summary.split("\n") if l.startswith("-")]
    assert len(shown_lines) == 5
    assert "3 ثغرة إضافية" in summary
    assert "8" in summary  # total count mentioned


def test_build_findings_summary_remainder_line_en():
    summary = groq_analyzer._build_findings_summary(_findings(7), lang="en")
    assert "2 more finding(s)" in summary
    assert "total findings: 7" in summary


def test_build_findings_summary_includes_only_type_severity_parameter():
    findings = [{
        "type": "sqli", "severity": "Critical", "parameter": "id",
        "evidence": "SUPER LONG EVIDENCE BLOB " * 50,
        "response_body": "huge body " * 100,
    }]
    summary = groq_analyzer._build_findings_summary(findings, lang="en")
    assert "sqli" in summary and "Critical" in summary and "id" in summary
    assert "SUPER LONG EVIDENCE BLOB" not in summary
    assert "huge body" not in summary


# ── generate_static_summary ────────────────────────────────────────────────


def test_generate_static_summary_counts_severities_and_most_common_type_ar():
    findings = [
        {"type": "xss", "severity": "High"},
        {"type": "xss", "severity": "High"},
        {"type": "sqli", "severity": "Critical"},
    ]
    result = groq_analyzer.generate_static_summary(findings, "example.com", lang="ar")
    assert "بدون ذكاء اصطناعي" in result
    assert "إجمالي الثغرات المكتشفة: 3" in result
    assert "High: 2" in result
    assert "أكثر نوع ثغرة تكراراً: xss" in result


def test_generate_static_summary_en():
    findings = [{"type": "lfi", "severity": "Medium"}]
    result = groq_analyzer.generate_static_summary(findings, "example.com", lang="en")
    assert "Total findings: 1" in result
    assert "Most common finding type: lfi" in result
    assert "General recommendation" in result


def test_generate_static_summary_handles_missing_fields_gracefully():
    findings = [{}, {"type": "xss"}]
    result = groq_analyzer.generate_static_summary(findings, "example.com", lang="en")
    assert "Total findings: 2" in result  # never raises on missing type/severity


# ── analyze_findings: empty input ──────────────────────────────────────────


def test_analyze_findings_returns_no_vulns_message_when_empty_ar():
    assert "لم يتم اكتشاف" in groq_analyzer.analyze_findings([], "example.com", lang="ar")


def test_analyze_findings_returns_no_vulns_message_when_empty_en():
    assert "No security vulnerabilities" in groq_analyzer.analyze_findings([], "example.com", lang="en")


# ── analyze_findings: caching ──────────────────────────────────────────────


def test_analyze_findings_uses_cache_on_second_identical_call(monkeypatch):
    call_count = []

    def fake_create(**kwargs):
        call_count.append(kwargs)
        return _FakeResponse("first analysis result")

    fake_client = type("Client", (), {"chat": type("Chat", (), {"completions": type("Completions", (), {"create": staticmethod(fake_create)})()})()})()
    monkeypatch.setattr(groq_analyzer, "_client", lambda: fake_client)

    findings = _findings(2)
    first = groq_analyzer.analyze_findings(findings, "example.com", lang="ar")
    second = groq_analyzer.analyze_findings(findings, "example.com", lang="ar")

    assert first == second == "first analysis result"
    assert len(call_count) == 1  # Groq only called once, second call served from cache


def test_analyze_findings_cache_key_distinguishes_lang_and_target(monkeypatch):
    call_count = []

    def fake_create(**kwargs):
        call_count.append(kwargs)
        return _FakeResponse("result")

    fake_client = type("Client", (), {"chat": type("Chat", (), {"completions": type("Completions", (), {"create": staticmethod(fake_create)})()})()})()
    monkeypatch.setattr(groq_analyzer, "_client", lambda: fake_client)

    findings = _findings(2)
    groq_analyzer.analyze_findings(findings, "example.com", lang="ar")
    groq_analyzer.analyze_findings(findings, "example.com", lang="en")  # different lang
    groq_analyzer.analyze_findings(findings, "other.com", lang="ar")  # different target

    assert len(call_count) == 3  # no cache hits across distinct keys


# ── analyze_findings: Groq call shape ──────────────────────────────────────


def test_analyze_findings_passes_max_tokens_400_and_configured_model(monkeypatch):
    captured = {}

    def fake_create(**kwargs):
        captured.update(kwargs)
        return _FakeResponse("ok")

    fake_client = type("Client", (), {"chat": type("Chat", (), {"completions": type("Completions", (), {"create": staticmethod(fake_create)})()})()})()
    monkeypatch.setattr(groq_analyzer, "_client", lambda: fake_client)

    groq_analyzer.analyze_findings(_findings(1), "example.com", lang="ar")

    assert captured["max_tokens"] == 400
    from config import GROQ_MODEL
    assert captured["model"] == GROQ_MODEL


# ── analyze_findings: fallback to static summary on total Groq failure ────


def test_analyze_findings_falls_back_to_static_summary_on_persistent_failure(monkeypatch):
    def fake_create(**kwargs):
        raise ConnectionError("Groq is down")

    fake_client = type("Client", (), {"chat": type("Chat", (), {"completions": type("Completions", (), {"create": staticmethod(fake_create)})()})()})()
    monkeypatch.setattr(groq_analyzer, "_client", lambda: fake_client)

    result = groq_analyzer.analyze_findings(_findings(2), "example.com", lang="ar")
    assert "بدون ذكاء اصطناعي" in result
    assert "إجمالي الثغرات المكتشفة: 2" in result


def test_analyze_findings_retries_transient_failures_before_succeeding(monkeypatch):
    attempts = []

    def fake_create(**kwargs):
        attempts.append(1)
        if len(attempts) < 2:
            raise ConnectionError("transient")
        return _FakeResponse("recovered analysis")

    fake_client = type("Client", (), {"chat": type("Chat", (), {"completions": type("Completions", (), {"create": staticmethod(fake_create)})()})()})()
    monkeypatch.setattr(groq_analyzer, "_client", lambda: fake_client)

    result = groq_analyzer.analyze_findings(_findings(2), "example.com", lang="ar")
    assert result == "recovered analysis"
    assert len(attempts) == 2


# ── analyze_findings: daily rate-limit error is not retried ───────────────


def test_analyze_findings_does_not_retry_daily_rate_limit_error(monkeypatch):
    attempts = []

    def fake_create(**kwargs):
        attempts.append(1)
        raise _FakeGroqRateLimitError()

    fake_client = type("Client", (), {"chat": type("Chat", (), {"completions": type("Completions", (), {"create": staticmethod(fake_create)})()})()})()
    monkeypatch.setattr(groq_analyzer, "_client", lambda: fake_client)

    result = groq_analyzer.analyze_findings(_findings(2), "example.com", lang="ar")

    assert len(attempts) == 1  # no retries -- daily cap won't clear in seconds
    assert "بدون ذكاء اصطناعي" in result  # still falls back to a static summary


def test_analyze_findings_retries_a_non_daily_429(monkeypatch):
    """A plain/TPM-style 429 (no '(TPD)' in the message) should still retry,
    since that resolves within the TPM window, unlike a daily cap."""
    attempts = []

    class _TpmRateLimitError(Exception):
        def __init__(self):
            self.status_code = 429
            self.body = {"error": {"message": "Rate limit reached (TPM)", "type": "tokens", "code": "rate_limit_exceeded"}}
            self.response = type("Resp", (), {"headers": {}})()

    def fake_create(**kwargs):
        attempts.append(1)
        if len(attempts) < 2:
            raise _TpmRateLimitError()
        return _FakeResponse("recovered after tpm retry")

    fake_client = type("Client", (), {"chat": type("Chat", (), {"completions": type("Completions", (), {"create": staticmethod(fake_create)})()})()})()
    monkeypatch.setattr(groq_analyzer, "_client", lambda: fake_client)

    result = groq_analyzer.analyze_findings(_findings(2), "example.com", lang="ar")
    assert result == "recovered after tpm retry"
    assert len(attempts) == 2


# ── analyze_findings: daily token budget preflight ─────────────────────────


def test_analyze_findings_returns_arabic_message_when_budget_exceeded(monkeypatch):
    called = []

    def fake_create(**kwargs):
        called.append(1)
        return _FakeResponse("should not happen")

    fake_client = type("Client", (), {"chat": type("Chat", (), {"completions": type("Completions", (), {"create": staticmethod(fake_create)})()})()})()
    monkeypatch.setattr(groq_analyzer, "_client", lambda: fake_client)
    monkeypatch.setattr(groq_analyzer, "get_default_daily_budget", lambda: type("B", (), {"would_exceed": lambda self, n: True})())

    result = groq_analyzer.analyze_findings(_findings(2), "example.com", lang="ar")
    assert "اليومي" in result
    assert called == []  # Groq never called once budget preflight rejects


def test_analyze_findings_returns_english_message_when_budget_exceeded(monkeypatch):
    monkeypatch.setattr(groq_analyzer, "get_default_daily_budget", lambda: type("B", (), {"would_exceed": lambda self, n: True})())
    result = groq_analyzer.analyze_findings(_findings(2), "example.com", lang="en")
    assert "daily AI usage limit" in result


def test_analyze_findings_records_usage_on_success(monkeypatch):
    recorded = []
    fake_budget = type("B", (), {
        "would_exceed": lambda self, n: False,
        "record": lambda self, n: recorded.append(n),
    })()
    monkeypatch.setattr(groq_analyzer, "get_default_daily_budget", lambda: fake_budget)

    def fake_create(**kwargs):
        return _FakeResponse("ok")

    fake_client = type("Client", (), {"chat": type("Chat", (), {"completions": type("Completions", (), {"create": staticmethod(fake_create)})()})()})()
    monkeypatch.setattr(groq_analyzer, "_client", lambda: fake_client)

    groq_analyzer.analyze_findings(_findings(2), "example.com", lang="ar")
    assert len(recorded) == 1 and recorded[0] > 0
