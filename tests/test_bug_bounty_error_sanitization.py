"""
Tests for modules/bug_bounty/{hackerone,bugcrowd}.py's exception handling.
Every authenticated-API call previously did `except Exception as e: return
{"error": str(e), ...}`, echoing the raw exception (connection details,
auth-failure bodies, internal URLs) straight back to the HTTP caller. Fixed
to log the real exception server-side (logger.exception) and return a
fixed, generic message instead.

Same _FakeAsyncClient convention as tests/test_hibp_integration.py: no real
network calls, httpx.AsyncClient is monkeypatched per module.
"""

import asyncio

import httpx
import pytest

import modules.bug_bounty.hackerone as hackerone
import modules.bug_bounty.bugcrowd as bugcrowd


def _run(coro):
    return asyncio.run(coro)


class _FakeAsyncClient:
    def __init__(self, exc=None, **kw):
        self._exc = exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, *a, **kw):
        raise self._exc

    async def post(self, *a, **kw):
        raise self._exc


_SENSITIVE = "Basic dXNlcjpzZWNyZXQtdG9rZW4tdmFsdWU="  # would appear in a raw auth-header exception


# ─── HackerOne ──────────────────────────────────────────────────────────────

def test_h1_get_program_scope_error_is_sanitized(monkeypatch):
    monkeypatch.setenv("HACKERONE_USERNAME", "user")
    monkeypatch.setenv("HACKERONE_API_TOKEN", "secret-token-value")
    boom = RuntimeError(f"connection reset: leaked internal detail {_SENSITIVE}")
    monkeypatch.setattr(hackerone.httpx, "AsyncClient", lambda *a, **kw: _FakeAsyncClient(exc=boom))

    result = _run(hackerone.get_program_scope("shopify"))
    assert result["error"] == hackerone._H1_ERROR_MESSAGE
    assert _SENSITIVE not in result["error"]
    assert "leaked internal detail" not in str(result)


def test_h1_submit_report_error_is_sanitized(monkeypatch):
    monkeypatch.setenv("HACKERONE_USERNAME", "user")
    monkeypatch.setenv("HACKERONE_API_TOKEN", "secret-token-value")
    boom = RuntimeError("upstream 401: invalid credentials for user:secret-token-value")
    monkeypatch.setattr(hackerone.httpx, "AsyncClient", lambda *a, **kw: _FakeAsyncClient(exc=boom))

    result = _run(hackerone.submit_report(
        program_handle="shopify", title="t", vulnerability_type="xss",
        severity="high", description="d", impact="i", steps_to_reproduce="s",
    ))
    assert result["status"] == "error"
    assert result["error"] == hackerone._H1_ERROR_MESSAGE
    assert "secret-token-value" not in result["error"]


def test_h1_get_my_reports_error_is_sanitized(monkeypatch):
    monkeypatch.setenv("HACKERONE_USERNAME", "user")
    monkeypatch.setenv("HACKERONE_API_TOKEN", "secret-token-value")
    boom = RuntimeError("raw internal exception text")
    monkeypatch.setattr(hackerone.httpx, "AsyncClient", lambda *a, **kw: _FakeAsyncClient(exc=boom))

    result = _run(hackerone.get_my_reports())
    assert result["error"] == hackerone._H1_ERROR_MESSAGE
    assert "raw internal exception text" not in result["error"]


def test_h1_authenticated_search_error_is_sanitized(monkeypatch):
    monkeypatch.setenv("HACKERONE_USERNAME", "user")
    monkeypatch.setenv("HACKERONE_API_TOKEN", "secret-token-value")
    boom = RuntimeError("raw internal exception text")

    # First call (public search) also needs to fail to reach the
    # authenticated fallback branch.
    calls = {"n": 0}

    def _client_factory(*a, **kw):
        calls["n"] += 1
        return _FakeAsyncClient(exc=boom)

    monkeypatch.setattr(hackerone.httpx, "AsyncClient", _client_factory)

    result = _run(hackerone.search_programs("shopify"))
    assert result["error"] == hackerone._H1_ERROR_MESSAGE
    assert "raw internal exception text" not in result["error"]


# ─── Bugcrowd ───────────────────────────────────────────────────────────────

def test_bc_get_targets_error_is_sanitized(monkeypatch):
    monkeypatch.setenv("BUGCROWD_API_TOKEN", "secret-bc-token")
    boom = RuntimeError("raw bugcrowd internal detail")
    monkeypatch.setattr(bugcrowd.httpx, "AsyncClient", lambda *a, **kw: _FakeAsyncClient(exc=boom))

    result = _run(bugcrowd.bc_get_targets("tesla"))
    assert result["error"] == bugcrowd._BC_ERROR_MESSAGE
    assert "raw bugcrowd internal detail" not in result["error"]


def test_bc_submit_report_error_is_sanitized(monkeypatch):
    monkeypatch.setenv("BUGCROWD_API_TOKEN", "secret-bc-token")
    boom = RuntimeError("upstream failure with secret-bc-token embedded")
    monkeypatch.setattr(bugcrowd.httpx, "AsyncClient", lambda *a, **kw: _FakeAsyncClient(exc=boom))

    result = _run(bugcrowd.bc_submit_report(
        program_code="tesla", title="t", description="d", severity="high",
    ))
    assert result["status"] == "error"
    assert result["error"] == bugcrowd._BC_ERROR_MESSAGE
    assert "secret-bc-token" not in result["error"]


# ─── Intigriti ──────────────────────────────────────────────────────────────

def test_ig_get_program_error_is_sanitized(monkeypatch):
    monkeypatch.setenv("INTIGRITI_API_TOKEN", "secret-ig-token")
    boom = RuntimeError("raw intigriti internal detail")
    monkeypatch.setattr(bugcrowd.httpx, "AsyncClient", lambda *a, **kw: _FakeAsyncClient(exc=boom))

    result = _run(bugcrowd.ig_get_program("proximus"))
    assert result["error"] == bugcrowd._IG_ERROR_MESSAGE
    assert "raw intigriti internal detail" not in result["error"]


def test_ig_list_programs_error_is_sanitized_and_falls_back_to_curated(monkeypatch):
    monkeypatch.setenv("INTIGRITI_API_TOKEN", "secret-ig-token")
    boom = RuntimeError("raw intigriti internal detail")
    monkeypatch.setattr(bugcrowd.httpx, "AsyncClient", lambda *a, **kw: _FakeAsyncClient(exc=boom))

    result = _run(bugcrowd.ig_list_programs())
    assert result["error"] == bugcrowd._IG_ERROR_MESSAGE
    assert result["programs"]  # still falls back to curated list, unaffected by the fix
