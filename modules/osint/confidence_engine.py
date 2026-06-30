"""
Confidence Engine
Scores OSINT findings for trustworthiness and classifies them by risk
severity, the way Maltego/SpiderFoot "weight" and "risk" their entities.

Two independent concerns live here:
  - calculate_confidence(): "how much should I believe this finding?"
  - classify_severity():    "how much should I care about this finding?"

Neither function performs any network I/O — they only reason over data
that unified_engine.py's sources already collected, so they are cheap to
call for every finding in a result set.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

# ── Source reliability ────────────────────────────────────────────────────────
# Fixed per-source trust weights (0-100), the base score a finding gets when
# reported by exactly one source. Calibrated by how the data is obtained:
#   - crt.sh / DNS / WHOIS: protocol-level / cryptographically-anchored facts
#     (a cert was actually issued, a record actually resolves) -> high (90/85)
#   - Amass: aggregates multiple passive APIs itself -> high (80)
#   - theHarvester / Holehe: scrape search engines / probe auth endpoints,
#     occasional false positives -> medium (70)
#   - Wayback: confirms a URL was *crawled*, not that the host still exists
#     or ever resolved publicly -> medium-low (65)
#   - Maigret: username-matching across 500+ sites has the highest false
#     positive rate of any source here -> lower (60)
SOURCE_RELIABILITY: dict[str, int] = {
    "crtsh": 90,
    "dns_full": 90,
    "whois": 85,
    "amass": 80,
    "theharvester": 70,
    "holehe": 70,
    "wayback": 65,
    "maigret": 60,
}
_DEFAULT_RELIABILITY = 50

_CONFIRMATION_BONUS = 15   # added per extra distinct source confirming a finding
_MAX_SCORE = 100
_MIN_SCORE = 0

# Freshness window thresholds, in days
_FRESH_DAYS = 90
_STALE_DAYS = 730


def _source_names(finding: dict, all_results: list[dict]) -> set[str]:
    """
    Resolve the set of distinct sources that reported `finding`.

    Prefers an explicit `sources` list (already merged by
    correlation_engine.deduplicate_and_merge). Falls back to scanning
    `all_results` for entries with the same `value`, so this function also
    works on raw, unmerged findings.
    """
    explicit = finding.get("sources")
    if explicit:
        return {s for s in explicit if s}

    names: set[str] = set()
    single = finding.get("source")
    if single:
        names.add(single)

    value = finding.get("value")
    if value is not None and all_results:
        for src_block in all_results:
            src_name = src_block.get("source")
            if not src_name:
                continue
            for r in src_block.get("results") or []:
                if r.get("value") == value:
                    names.add(src_name)
    return names


def _parse_timestamp(raw: Any) -> datetime | None:
    """Best-effort parse of the loose date strings our sources produce."""
    if not raw:
        return None
    text = str(raw).strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        m = re.match(r"(\d{4})-(\d{2})-(\d{2})", text)
        if not m:
            return None
        dt = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _freshness_adjustment(finding: dict) -> int:
    """
    +5 if the finding's timestamp is recent (<90 days old), -10 if it's
    stale (>2 years old), 0 if unknown or in between.

    Recency matters because passive sources like crt.sh/Wayback report
    historical data — a certificate issued yesterday is strong evidence the
    host is live *today*; one issued in 2019 says much less.
    """
    raw_ts = (
        finding.get("timestamp")
        or finding.get("not_before")
        or finding.get("last_seen")
    )
    dt = _parse_timestamp(raw_ts)
    if dt is None:
        return 0
    age_days = (datetime.now(timezone.utc) - dt).days
    if age_days < _FRESH_DAYS:
        return 5
    if age_days > _STALE_DAYS:
        return -10
    return 0


def calculate_confidence(finding: dict, all_results: list[dict]) -> int:
    """
    Score a finding's trustworthiness from 0-100.

    Algorithm:
      1. base = the reliability weight (SOURCE_RELIABILITY) of the single
         *most trusted* source that reported this finding.
      2. + _CONFIRMATION_BONUS (15) for every *additional* distinct source
         that independently reported the same entity — cross-source
         corroboration is the strongest confidence signal in OSINT: a
         subdomain seen via both crt.sh and live DNS resolution is far
         more credible than one seen via a single passive source.
      3. +/- a small freshness adjustment if the finding carries a
         timestamp (see _freshness_adjustment).
      4. clamp to [0, 100].
    """
    sources = _source_names(finding, all_results)
    if not sources:
        return _MIN_SCORE

    base = max(SOURCE_RELIABILITY.get(s, _DEFAULT_RELIABILITY) for s in sources)
    corroboration_bonus = (len(sources) - 1) * _CONFIRMATION_BONUS
    score = base + corroboration_bonus + _freshness_adjustment(finding)
    return max(_MIN_SCORE, min(_MAX_SCORE, score))


# ── Severity classification ───────────────────────────────────────────────────

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _days_between(raw: Any, *, from_now: bool) -> int | None:
    dt = _parse_timestamp(raw)
    if dt is None:
        return None
    now = datetime.now(timezone.utc)
    delta = (dt - now) if from_now else (now - dt)
    return delta.days


def classify_severity(finding: dict) -> str:
    """
    Classify a single finding's security relevance as one of:
    critical / high / medium / low / info.

    This is a rule-based heuristic over metadata the passive sources
    already collected — it never makes an extra network call (e.g. it will
    not actively probe a subdomain for TLS; it only honors an explicit
    `tls` flag if a source already attached one).

    Rules (first match wins):
      - whois_record expiring within 30 days  -> critical (hijack/lapse risk)
      - subdomain explicitly flagged tls=False -> high (cleartext exposure)
      - whois_record registered within last 30 days -> medium (fresh infra,
        common in phishing setups)
      - SPF/DMARC missing                      -> medium (spoofing exposure)
      - exposed email address                  -> medium (PII exposure)
      - registered account on an external platform -> medium (identity pivot)
      - subdomain (TLS state unknown)           -> low (attack surface)
      - public social-media profile             -> low
      - SPF/DMARC record present, raw DNS record, WHOIS far from expiry,
        anything unrecognized                   -> info
    """
    ftype = (finding.get("type") or "").lower()

    if ftype == "whois_record":
        days_left = _days_between(finding.get("expiration_date"), from_now=True)
        if days_left is not None and days_left <= 30:
            return "critical"

    if ftype == "subdomain" and finding.get("tls") is False:
        return "high"

    if ftype == "whois_record":
        days_old = _days_between(finding.get("creation_date"), from_now=False)
        if days_old is not None and days_old <= 30:
            return "medium"
        return "info"

    if ftype in ("spf_status", "dmarc_status") and str(finding.get("value", "")).lower() == "missing":
        return "medium"

    if ftype == "email":
        return "medium"

    if ftype == "account":
        return "medium"

    if ftype == "subdomain":
        return "low"

    if ftype == "profile":
        return "low"

    return "info"
