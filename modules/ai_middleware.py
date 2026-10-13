"""Asynchronous, sampled AI intent analysis. It sits beside the DPI engines and never runs inline in front of them.

Design constraints (see docs/architecture/ai-brain-phase1.md):

- Nothing here is called on the request path of the NGFW / WAF engines.
  modules/firewall/ngfw_v2.py:deep_inspect() and
  modules/firewall/ai_firewall.py:inspect_request() make their ALLOW / ALERT /
  BLOCK decision exactly as before; this module only ever *reads* a finished
  decision and may enqueue a sampled copy for offline analysis.
- AnalysisQueue.submit() is synchronous, non-blocking, and never raises.
  It returns a bool and does not hand the verdict back to the caller. The
  verdict goes only to an audit sink.
- Only payloads that the existing rule engine already marked as anomalous
  are eligible (action ALERT or BLOCK, the same definition deep_inspect()
  uses for its "anomalies" counter). Only a configurable fraction of those
  is analysed. The default rate is 0, so nothing is sent unless
  AI_MIDDLEWARE_SAMPLE_RATE is set explicitly.
- Payloads are redacted (redact()) before any provider sees them.
- Verdicts are stored in ai_blocked_logs as audit records with
  action="flagged". They are never used as an automatic block. The table is
  on its own metadata (AuditBase), so web/database.py:init_db()'s create_all
  does NOT create it at startup. It is created only by running
  web/migrate_add_ai_blocked_logs_table.py by hand.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import random
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Awaitable, Callable, Optional

from sqlalchemy import Boolean, CheckConstraint, Column, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase

logger = logging.getLogger("ai.middleware")

# Environment variable names. Only the names live here, never the values.
GROQ_API_KEY_ENV = "GROQ_API_KEY"
SAMPLE_RATE_ENV = "AI_MIDDLEWARE_SAMPLE_RATE"

MAX_PAYLOAD_CHARS = 4000          # cap on what is redacted and sent to a provider
MAX_EXCERPT_CHARS = 500           # cap on the redacted excerpt stored in the audit row
MAX_TYPE_CHARS = 64
DEFAULT_PROVIDER_TIMEOUT = 15.0   # seconds
DEFAULT_QUEUE_MAXSIZE = 1000

# The existing rule engines' own "anomalous" decisions (ngfw_v2 uses
# upper-case, ai_firewall lower-case; compared case-insensitively).
ANOMALOUS_ACTIONS = frozenset({"ALERT", "BLOCK"})

AUDIT_ACTION = "flagged"


# ── Redaction ────────────────────────────────────────────────────────────────

_SECRET_KEY_NAMES = (
    r"pass(?:word|wd)?|pwd|secret|client_secret|token|access_token|refresh_token|"
    r"id_token|auth_token|session(?:id)?|api[_-]?key|apikey|x-api-key|private_key"
)

# Order matters: header-level and key/value rules run before the generic
# format rules, so a bearer token is labelled as a token rather than a key.
_REDACTION_RULES: list[tuple[re.Pattern, Any]] = [
    # Authorization: Bearer <tok> / Basic <b64>, alone or as a header line
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9\-._~+/]{8,}=*"), r"\1 [REDACTED_TOKEN]"),
    (re.compile(r"(?i)\b(basic)\s+[A-Za-z0-9+/]{8,}=*"), r"\1 [REDACTED_TOKEN]"),
    # Cookie / Set-Cookie headers: mask the whole value up to end of line
    (re.compile(r"(?im)^(\s*(?:set-)?cookie\s*:\s*).+$"), r"\1[REDACTED_COOKIE]"),
    (re.compile(r'(?i)("(?:set-)?cookie"\s*:\s*")[^"]*(")'), r"\1[REDACTED_COOKIE]\2"),
    # JSON-style "password": "value"
    (re.compile(r'(?i)("[\w-]*(?:' + _SECRET_KEY_NAMES + r')"\s*:\s*")[^"]*(")'), r"\1[REDACTED_SECRET]\2"),
    # header-style X-Api-Key: value
    (re.compile(r"(?im)^(\s*(?:x-api-key|x-auth-token|api-key)\s*:\s*).+$"), r"\1[REDACTED_SECRET]"),
    # query/form-style password=value, token=value, api_key=value
    (re.compile(r"(?i)\b([\w-]*(?:" + _SECRET_KEY_NAMES + r"))(\s*[=:]\s*)[^\s&;,\"']+"), r"\1\2[REDACTED_SECRET]"),
    # well-known API key / token formats
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"), "[REDACTED_TOKEN]"),  # JWT
    (re.compile(r"\b(?:gsk|sk|pk|rk)[-_](?:live_|test_|proj-)?[A-Za-z0-9]{16,}"), "[REDACTED_KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "[REDACTED_KEY]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "[REDACTED_KEY]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "[REDACTED_KEY]"),
    # emails
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    # IPv4
    (re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"),
     "[REDACTED_IP]"),
]


def redact(text: str) -> str:
    """Mask credentials and identifying data before text leaves the process."""
    if not text:
        return ""
    out = str(text)
    for pattern, replacement in _REDACTION_RULES:
        out = pattern.sub(replacement, out)
    return out


# ── Providers ────────────────────────────────────────────────────────────────

class AIProvider(ABC):
    """A backend that classifies one (already redacted) payload."""

    name: str = "abstract"

    @abstractmethod
    async def analyze(self, text: str) -> dict:
        """Return a dict with is_malicious / type / confidence. May raise."""


_SYSTEM_PROMPT = (
    "You are a web application security classifier. Classify the intent of the "
    "single HTTP payload you are given. Sensitive values have been replaced by "
    "[REDACTED_*] placeholders; do not treat placeholders as malicious. "
    'Respond with JSON only: {"is_malicious": boolean, "type": string '
    '(one of "sqli", "xss", "lfi", "cmdi", "ssrf", "c2", "scanner", "benign", "other"), '
    '"confidence": number between 0 and 1}.'
)


class GroqProvider(AIProvider):
    """Groq chat-completions provider (async SDK, already in requirements.txt).

    The key is read from the environment variable named GROQ_API_KEY when
    analyze() is called. It is never stored in code, logs, or exceptions.
    """

    name = "groq"

    def __init__(self, model: Optional[str] = None, timeout: float = DEFAULT_PROVIDER_TIMEOUT):
        if model is None:
            from config import GROQ_MODEL
            model = GROQ_MODEL
        self.model = model
        self.timeout = timeout

    async def analyze(self, text: str) -> dict:
        api_key = os.environ.get(GROQ_API_KEY_ENV)
        if not api_key:
            raise RuntimeError(f"{GROQ_API_KEY_ENV} is not set")
        from groq import AsyncGroq

        client = AsyncGroq(api_key=api_key, timeout=self.timeout, max_retries=0)
        completion = await client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": text},
            ],
            response_format={"type": "json_object"},
            temperature=0,
            max_tokens=120,
        )
        content = completion.choices[0].message.content or ""
        parsed = json.loads(content)
        if not isinstance(parsed, dict):
            raise ValueError("provider returned non-object JSON")
        return parsed


class FakeProvider(AIProvider):
    """Deterministic provider for tests. It makes no network calls.

    `response` is returned as-is (so malformed output can be simulated);
    `exc`, if set, is raised instead. Every text it receives is recorded
    in `calls` so tests can assert redaction happened first.
    """

    name = "fake"

    def __init__(self, response: Any = None, exc: Optional[BaseException] = None, delay: float = 0.0):
        self.response = response if response is not None else {
            "is_malicious": False, "type": "benign", "confidence": 0.9,
        }
        self.exc = exc
        self.delay = delay
        self.calls: list[str] = []

    async def analyze(self, text: str) -> dict:
        self.calls.append(text)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.exc is not None:
            raise self.exc
        return self.response


# ── Intent analysis ──────────────────────────────────────────────────────────

def _fallback(error: str) -> dict:
    return {"is_malicious": False, "type": "unknown", "confidence": 0.0, "error": error}


def _validate_verdict(raw: Any) -> dict:
    """Return a clean verdict, or raise ValueError describing the problem."""
    if not isinstance(raw, dict):
        raise ValueError("output is not an object")
    is_mal = raw.get("is_malicious")
    vtype = raw.get("type")
    conf = raw.get("confidence")
    if not isinstance(is_mal, bool):
        raise ValueError("is_malicious must be a boolean")
    if not isinstance(vtype, str) or not vtype.strip():
        raise ValueError("type must be a non-empty string")
    # bool is a subclass of int; reject it explicitly
    if isinstance(conf, bool) or not isinstance(conf, (int, float)):
        raise ValueError("confidence must be a number")
    conf = float(conf)
    if not math.isfinite(conf) or not 0.0 <= conf <= 1.0:
        raise ValueError("confidence must be within [0, 1]")
    return {"is_malicious": is_mal, "type": vtype.strip()[:MAX_TYPE_CHARS], "confidence": conf}


async def analyze_intent(
    payload: str,
    provider: AIProvider,
    timeout: float = DEFAULT_PROVIDER_TIMEOUT,
) -> dict:
    """Classify a payload's intent. Never raises an Exception.

    Returns {"is_malicious": bool, "type": str, "confidence": float}; on
    provider failure, timeout, or schema violation returns the safe fallback
    {"is_malicious": False, "type": "unknown", "confidence": 0.0, "error": ...}.
    The error string names the failure class only, never provider output or
    payload content.
    """
    try:
        text = redact(str(payload or "")[:MAX_PAYLOAD_CHARS])
        raw = await asyncio.wait_for(provider.analyze(text), timeout=timeout)
    except asyncio.TimeoutError:
        return _fallback("provider_timeout")
    except Exception as exc:  # noqa: BLE001 — must never propagate
        logger.warning("AI provider %s failed: %s", getattr(provider, "name", "?"), type(exc).__name__)
        return _fallback(f"provider_error: {type(exc).__name__}")
    try:
        return _validate_verdict(raw)
    except ValueError as exc:
        return _fallback(f"malformed_output: {exc}")


# ── Sampling policy ──────────────────────────────────────────────────────────

def _parse_rate(value: Optional[str]) -> float:
    try:
        rate = float(value) if value not in (None, "") else 0.0
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(rate):
        return 0.0
    return min(1.0, max(0.0, rate))


@dataclass(frozen=True)
class SamplingPolicy:
    """Which already-decided DPI results may be sent for AI analysis."""

    rate: float = 0.0

    @classmethod
    def from_env(cls) -> "SamplingPolicy":
        """Read AI_MIDDLEWARE_SAMPLE_RATE (0..1). Unset/invalid → 0 (disabled)."""
        return cls(rate=_parse_rate(os.environ.get(SAMPLE_RATE_ENV)))

    @property
    def enabled(self) -> bool:
        return self.rate > 0.0

    @staticmethod
    def is_eligible(dpi_result: Any) -> bool:
        """True only if the existing rule engine itself flagged the request."""
        if not isinstance(dpi_result, dict):
            return False
        action = dpi_result.get("action")
        return isinstance(action, str) and action.upper() in ANOMALOUS_ACTIONS

    def should_sample(self, dpi_result: Any, rng: Callable[[], float] = random.random) -> bool:
        if not self.enabled or not self.is_eligible(dpi_result):
            return False
        return rng() < self.rate


# ── Audit storage ────────────────────────────────────────────────────────────

class AuditBase(DeclarativeBase):
    """Deliberately separate from web.database.Base, so init_db() never creates this table."""


class AIBlockedLog(AuditBase):
    """Audit record of an AI verdict. action is always 'flagged' and never triggers a block."""

    __tablename__ = "ai_blocked_logs"
    __table_args__ = (
        CheckConstraint("action = 'flagged'", name="ck_ai_blocked_logs_action_flagged"),
    )

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    action = Column(String(16), nullable=False, default=AUDIT_ACTION)
    is_malicious = Column(Boolean, nullable=False, default=False)
    verdict_type = Column(String(MAX_TYPE_CHARS), nullable=False, default="unknown")
    confidence = Column(Float, nullable=False, default=0.0)
    error = Column(String(160), nullable=True)
    provider = Column(String(32), nullable=False)
    dpi_engine = Column(String(32), nullable=True)
    dpi_action = Column(String(16), nullable=True)
    dpi_score = Column(Float, nullable=True)
    payload_sha256 = Column(String(64), nullable=False, index=True)
    payload_excerpt = Column(Text, nullable=True)  # redacted, truncated
    user_id = Column(Integer, nullable=True, index=True)


def build_audit_record(
    payload: str,
    verdict: dict,
    dpi_result: dict,
    provider_name: str,
    dpi_engine: Optional[str] = None,
    user_id: Optional[int] = None,
) -> dict:
    score = dpi_result.get("threat_score", dpi_result.get("risk_score"))
    return {
        "action": AUDIT_ACTION,
        "is_malicious": bool(verdict.get("is_malicious", False)),
        "verdict_type": str(verdict.get("type", "unknown"))[:MAX_TYPE_CHARS],
        "confidence": float(verdict.get("confidence", 0.0)),
        "error": (str(verdict["error"])[:160] if verdict.get("error") else None),
        "provider": provider_name[:32],
        "dpi_engine": dpi_engine,
        "dpi_action": str(dpi_result.get("action"))[:16],
        "dpi_score": float(score) if isinstance(score, (int, float)) and not isinstance(score, bool) else None,
        "payload_sha256": hashlib.sha256(str(payload or "").encode("utf-8", "replace")).hexdigest(),
        "payload_excerpt": redact(str(payload or "")[:MAX_PAYLOAD_CHARS])[:MAX_EXCERPT_CHARS],
        "user_id": user_id,
    }


AuditSink = Callable[[dict], Awaitable[None]]


class SqlAuditSink:
    """Writes audit records to ai_blocked_logs via an async session factory."""

    def __init__(self, session_factory):
        self._session_factory = session_factory

    async def __call__(self, record: dict) -> None:
        row = AIBlockedLog(**{**record, "action": AUDIT_ACTION})
        async with self._session_factory() as session:
            session.add(row)
            await session.commit()


class MemoryAuditSink:
    """In-process sink for tests / local inspection."""

    def __init__(self):
        self.records: list[dict] = []

    async def __call__(self, record: dict) -> None:
        self.records.append(dict(record))


# ── Queue ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class _Job:
    payload: str
    dpi_result: dict
    dpi_engine: Optional[str]
    user_id: Optional[int]


class AnalysisQueue:
    """Bounded asyncio queue + background workers for offline analysis.

    submit() is the only call a request handler would make. It is
    synchronous and O(1), it drops jobs when the queue is full, and it
    returns nothing the caller could act on except a bool.
    """

    def __init__(
        self,
        provider: AIProvider,
        sink: AuditSink,
        policy: Optional[SamplingPolicy] = None,
        maxsize: int = DEFAULT_QUEUE_MAXSIZE,
        workers: int = 1,
        timeout: float = DEFAULT_PROVIDER_TIMEOUT,
        rng: Callable[[], float] = random.random,
    ):
        self.provider = provider
        self.sink = sink
        self.policy = policy if policy is not None else SamplingPolicy.from_env()
        self.timeout = timeout
        self._rng = rng
        self._queue: asyncio.Queue[_Job] = asyncio.Queue(maxsize=maxsize)
        self._n_workers = max(1, workers)
        self._tasks: list[asyncio.Task] = []
        self.dropped = 0

    def submit(
        self,
        payload: str,
        dpi_result: dict,
        dpi_engine: Optional[str] = None,
        user_id: Optional[int] = None,
    ) -> bool:
        """Enqueue a sampled copy if eligible. Never blocks, never raises."""
        try:
            if not self.policy.should_sample(dpi_result, self._rng):
                return False
            # Snapshot only the fields needed, so later mutation of the
            # caller's dict has no effect here (and vice versa).
            snapshot = {k: dpi_result.get(k) for k in ("action", "threat_score", "risk_score")}
            self._queue.put_nowait(_Job(str(payload or "")[:MAX_PAYLOAD_CHARS], snapshot, dpi_engine, user_id))
            return True
        except asyncio.QueueFull:
            self.dropped += 1
            return False
        except Exception as exc:  # noqa: BLE001
            logger.warning("AI analysis submit failed: %s", type(exc).__name__)
            return False

    async def _process(self, job: _Job) -> None:
        verdict = await analyze_intent(job.payload, self.provider, timeout=self.timeout)
        record = build_audit_record(
            job.payload, verdict, job.dpi_result, self.provider.name, job.dpi_engine, job.user_id,
        )
        try:
            await self.sink(record)
        except Exception as exc:  # noqa: BLE001
            logger.warning("AI audit write failed: %s", type(exc).__name__)

    async def _worker(self) -> None:
        while True:
            job = await self._queue.get()
            try:
                await self._process(job)
            finally:
                self._queue.task_done()

    def start(self) -> None:
        if self._tasks:
            return
        self._tasks = [asyncio.create_task(self._worker()) for _ in range(self._n_workers)]

    async def drain(self) -> None:
        """Wait until every queued job has been processed."""
        await self._queue.join()

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []

    @property
    def pending(self) -> int:
        return self._queue.qsize()
