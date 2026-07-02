"""AI triage of already-detected scanner findings.

Takes a single finding dict (as produced by modules/vuln/*.py, already
carrying a waf_aware_classifier verdict, status_code, and response_body)
and asks Groq for a second-opinion verdict: is this actually exploitable,
a false positive, or unclear enough to need a human. This is triage of an
existing signal, not vulnerability discovery — the model is only ever
asked to judge evidence that's already in front of it.
"""

import asyncio
import json
import logging

from config import GROQ_CONCURRENCY_LIMIT, GROQ_MODEL
from modules.ai.groq_analyzer import _client
from modules.ai.groq_client_utils import call_groq_sync_with_retry
from modules.ai.rate_limiter import (
    TokenBucketLimiter,
    TPDExhaustedException,
    estimate_tokens,
    parse_tpd_state_from_error,
)

logger = logging.getLogger("ai.triage_engine")

VALID_VERDICTS = {"CONFIRMED", "LIKELY_FALSE_POSITIVE", "NEEDS_MANUAL_REVIEW"}

_MAX_BODY_CHARS = 1500


def _build_prompt(finding: dict) -> str:
    target = finding.get("url") or finding.get("target") or "unknown"
    status_code = finding.get("status_code", "unknown")
    response_body = finding.get("response_body") or ""
    if len(response_body) > _MAX_BODY_CHARS:
        response_body = response_body[:_MAX_BODY_CHARS] + "...(truncated)"

    return f"""You are a senior application security engineer performing triage on findings that an automated scanner already flagged. Your job is NOT to discover new vulnerabilities — the finding below already exists. Your job is to judge, from the evidence given, whether it is a real confirmed issue, a false positive, or something a human needs to look at.

Finding to triage:
- Type: {finding.get("type", "unknown")}
- Severity: {finding.get("severity", "unknown")}
- Target: {target}
- Parameter: {finding.get("parameter", "")}
- Payload: {finding.get("payload", "")}
- Existing scanner verdict/evidence: {finding.get("verdict", "")} / {finding.get("evidence", "")}
- WAF detected: {finding.get("waf_detected", "")}
- HTTP status code: {status_code}
- Response body (may be truncated or absent): {response_body if response_body else "(not captured)"}

Classification criteria:
- CONFIRMED: the status code and response body pattern clearly confirm the vulnerability is real and exploitable (e.g. payload reflected unencoded in a 200 response, a SQL/DB error string leaked, a redirect to an attacker-controlled host actually happened).
- LIKELY_FALSE_POSITIVE: the response shows the request was blocked/rejected by a WAF, returned an error/invalid-endpoint status, the payload appears encoded/escaped, or the behavior looks like normal unaffected application behavior.
- NEEDS_MANUAL_REVIEW: the evidence is ambiguous, incomplete (e.g. missing response_body or status_code), or contradictory — not enough signal to decide confidently either way.

Respond with ONLY a JSON object with these exact fields:
{{
  "triage_verdict": "CONFIRMED" | "LIKELY_FALSE_POSITIVE" | "NEEDS_MANUAL_REVIEW",
  "triage_confidence": 0.0 to 1.0,
  "triage_reason": "one or two short sentences explaining why, in the same language as the finding's evidence text"
}}

Example:
- Given a finding with status_code 200 and response_body containing the raw unencoded payload "<script>alert(1)</script>" reflected in the HTML -> {{"triage_verdict": "CONFIRMED", "triage_confidence": 0.9, "triage_reason": "The payload is reflected unencoded in the HTML response with a 200 status, confirming the XSS is exploitable."}}
- Given a finding with status_code 403 and response_body containing a WAF block page -> {{"triage_verdict": "LIKELY_FALSE_POSITIVE", "triage_confidence": 0.85, "triage_reason": "The request was blocked by a WAF (HTTP 403), so the payload never reached the application."}}"""


def _fallback(reason: str) -> dict:
    return {
        "triage_verdict": "NEEDS_MANUAL_REVIEW",
        "triage_confidence": 0.0,
        "triage_reason": f"AI triage unavailable: {reason}",
    }


def _tpd_fallback(reset_time_iso: str) -> dict:
    return {
        "triage_verdict": "NEEDS_MANUAL_REVIEW",
        "triage_confidence": 0.0,
        "triage_reason": f"Daily token quota (TPD) exhausted. Resets at {reset_time_iso}.",
    }


def classify_finding(finding: dict, *, _capture_exception: list[BaseException] | None = None) -> dict:
    """Classify a single scanner finding via Groq. Never raises — falls back to NEEDS_MANUAL_REVIEW.

    `_capture_exception` is internal-only: when classify_findings_batch passes
    a list here, the exception that triggered the fallback (if any) is
    appended to it, so the caller can inspect a real Groq error (e.g. to
    detect and seed real TPD state) without changing this function's
    never-raises contract for any other caller.
    """
    try:
        prompt = _build_prompt(finding)
        client = _client()
        response = call_groq_sync_with_retry(
            client.chat.completions.create,
            model=GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300,
            temperature=0.1,
            response_format={"type": "json_object"},
            retry_delays=(1, 2, 4, 8),
        )
        content = response.choices[0].message.content.strip()
        try:
            result = json.loads(content)
        except json.JSONDecodeError as exc:
            logger.warning("Triage response was not valid JSON: %s", exc)
            return _fallback("invalid JSON response from model")

        verdict = result.get("triage_verdict")
        if verdict not in VALID_VERDICTS:
            logger.warning("Triage response had unexpected verdict: %r", verdict)
            return _fallback(f"unexpected verdict from model: {verdict!r}")

        try:
            confidence = float(result.get("triage_confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))

        reason = result.get("triage_reason") or ""

        return {
            "triage_verdict": verdict,
            "triage_confidence": confidence,
            "triage_reason": reason,
        }
    except Exception as exc:
        if _capture_exception is not None:
            _capture_exception.append(exc)
        logger.warning("AI triage call failed: %s", exc)
        return _fallback(str(exc))


async def classify_findings_batch(
    findings: list[dict], concurrency_limit: int | None = None
) -> tuple[list[dict], dict]:
    """Classify multiple findings concurrently, preserving input order.

    classify_finding itself is a sync call (sync Groq client), so each call
    is run in a worker thread via asyncio.to_thread; a semaphore caps how
    many run at once. One finding's failure never affects the others — it
    just gets the same NEEDS_MANUAL_REVIEW fallback classify_finding already
    returns on error.

    A TokenBucketLimiter shared across the whole batch is a second, separate
    layer: it caps how many tokens/minute (TPM) and tokens/day (TPD) the
    batch spends, which is what Groq's account-level caps actually enforce —
    a low concurrency limit alone doesn't stop the batch from exceeding
    either if each call is small and fast. Concurrency and token-rate are
    independent constraints, so the semaphore's behavior above is untouched.

    TPM and TPD exhaustion are handled differently on purpose. TPM resolves
    in seconds-to-minutes, so TokenBucketLimiter.acquire() waits it out
    (dynamic sleep) exactly as before. TPD resolves in hours, so waiting is
    unacceptable — the first TPDExhaustedException seen here immediately
    stops the whole batch from making further Groq calls: every finding not
    already in flight (including the one that just hit the exception) gets
    NEEDS_MANUAL_REVIEW with the TPD reset time, with no retry. Findings
    that already completed successfully before that point keep their
    results untouched.

    TokenBucketLimiter's TPD window only tracks *this batch's own* estimated
    spend, starting from 0 — it has no way to know the real account is
    already near/at its daily cap from usage outside this process. Without
    more, that means an account already near TPD externally would sail past
    every local acquire() check and hit real 429s one by one, each paying
    the slow retry-then-fallback path individually (confirmed live). To
    close that gap, the first time a real Groq call here fails with a
    genuine TPD 429 (parsed via parse_tpd_state_from_error), the shared
    rate_limiter is seeded with the real Used/Limit/retry-after from that
    error — so the very next finding's acquire() call raises
    TPDExhaustedException immediately instead of also making a doomed real
    call.

    Returns (results, summary) where results is the per-finding list in
    input order (same shape as before) and summary is:
    {"succeeded": int, "deferred_tpd": int, "tpd_reset_time": str | None}.
    """
    limit = concurrency_limit if concurrency_limit is not None else GROQ_CONCURRENCY_LIMIT
    semaphore = asyncio.Semaphore(limit)
    rate_limiter = TokenBucketLimiter()

    tpd_exhausted = asyncio.Event()
    tpd_reset_time: list[str] = []
    counts = {"succeeded": 0, "deferred_tpd": 0}

    async def _classify_one(finding: dict) -> dict:
        async with semaphore:
            if tpd_exhausted.is_set():
                counts["deferred_tpd"] += 1
                return _tpd_fallback(tpd_reset_time[0])
            try:
                await rate_limiter.acquire(estimate_tokens(finding))
            except TPDExhaustedException as exc:
                if not tpd_exhausted.is_set():
                    tpd_reset_time.append(exc.reset_time_iso)
                    tpd_exhausted.set()
                counts["deferred_tpd"] += 1
                return _tpd_fallback(tpd_reset_time[0])
            try:
                captured_exception: list[BaseException] = []
                result = await asyncio.to_thread(
                    classify_finding, finding, _capture_exception=captured_exception
                )
            except Exception as exc:
                logger.warning("AI triage call failed: %s", exc)
                return _fallback(str(exc))

            if captured_exception:
                tpd_state = parse_tpd_state_from_error(captured_exception[0])
                if tpd_state is not None:
                    reset_dt = await rate_limiter.seed_real_tpd_usage(
                        tpd_state.used, tpd_state.limit, tpd_state.retry_after_seconds
                    )
                    if not tpd_exhausted.is_set():
                        tpd_reset_time.append(reset_dt.isoformat())
                        tpd_exhausted.set()
                    counts["deferred_tpd"] += 1
                    return _tpd_fallback(tpd_reset_time[0])

            counts["succeeded"] += 1
            return result

    results = list(await asyncio.gather(*(_classify_one(f) for f in findings)))
    summary = {
        "succeeded": counts["succeeded"],
        "deferred_tpd": counts["deferred_tpd"],
        "tpd_reset_time": tpd_reset_time[0] if tpd_reset_time else None,
    }
    return results, summary
