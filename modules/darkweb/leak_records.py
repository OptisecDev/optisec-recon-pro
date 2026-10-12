"""
Dark Web Monitoring — leak-record normalization, severity and dedupe.

Every credential-leak provider (LeakCheck, BreachDirectory, Leak-Lookup,
HIBP) is reduced to the same per-record shape before anything is stored:

    {provider, source_name, leak_date, matched_field, matched_value,
     leaked_fields}

`matched_value` is the raw email/username/domain that matched; it only lives
in memory long enough to fingerprint and mask it — alerts store the masked
form (modules/darkweb/targets.mask_value). `leaked_fields` is a list of
canonical field *names* ("password", "password_hash", "ip", "name", ...);
leaked values (passwords above all) are never kept.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone

from modules.darkweb.targets import mask_value

# ── 1. Explicit per-provider query types ────────────────────────────────────
# Never "auto": LeakCheck's auto-detection is what turned the bare word
# "tp-link" into a username search. Unsupported target types raise instead of
# silently falling back.

LEAKCHECK_QUERY_TYPES = {"domain": "domain", "email": "email", "username": "username"}
LEAKLOOKUP_QUERY_TYPES = {"domain": "domain", "email": "email_address", "username": "username"}
# BreachDirectory (RapidAPI) has no per-type email/username func — "sources"
# is its explicit account lookup, "domain" its domain lookup.
BREACHDIRECTORY_FUNCS = {"domain": "domain", "email": "sources", "username": "sources"}


def query_type_for(provider: str, target_type: str) -> str:
    table = {
        "leakcheck": LEAKCHECK_QUERY_TYPES,
        "leaklookup": LEAKLOOKUP_QUERY_TYPES,
        "breachdirectory": BREACHDIRECTORY_FUNCS,
    }[provider]
    if target_type not in table:
        raise ValueError(f"{provider}: unsupported target_type {target_type!r}")
    return table[target_type]


# ── 2. API error messages ───────────────────────────────────────────────────

_HTTP_ERRORS = {
    400: ("bad request — the query or its type was rejected", "طلب غير صالح — تم رفض الاستعلام أو نوعه"),
    401: ("missing or invalid API key", "مفتاح API مفقود أو غير صالح"),
    403: ("access denied — plan limit reached or key not authorized", "تم رفض الوصول — تجاوز حد الخطة أو المفتاح غير مخوّل"),
    422: ("the query could not be processed for this type", "تعذّرت معالجة الاستعلام لهذا النوع"),
    429: ("rate limit exceeded — try again later", "تم تجاوز حد الطلبات — حاول لاحقاً"),
}


def api_error(provider: str, status: int | None, detail: str | None = None) -> dict:
    """{error, error_ar, status} for a failed provider call — the English
    `error` string keeps the shape existing consumers already read."""
    en, ar = _HTTP_ERRORS.get(status, ("upstream error", "خطأ من مزوّد الخدمة"))
    suffix = f" (HTTP {status})" if status else ""
    detail_part = f": {detail}" if detail else ""
    return {
        "error": f"{provider}: {en}{suffix}{detail_part}",
        "error_ar": f"{provider}: {ar}{suffix}",
        "status": status,
    }


# ── 3. Field canonicalization ───────────────────────────────────────────────

_FIELD_ALIASES = {
    "password": "password", "pass": "password", "plaintext": "password",
    # HIBP's "Passwords" data class doesn't say plain vs hashed; most are hashed.
    "passwords": "password_hash",
    "hash": "password_hash", "password_hash": "password_hash", "phash": "password_hash",
    "sha1": "password_hash", "md5": "password_hash", "bcrypt": "password_hash", "salt": "password_hash",
    "ip": "ip", "ip1": "ip", "ip2": "ip", "ip_address": "ip", "ipaddress": "ip", "last_ip": "ip",
    "ip addresses": "ip",
    "name": "name", "first_name": "name", "last_name": "name", "fullname": "name", "full_name": "name",
    "names": "name",
    "phone": "phone", "phone_number": "phone", "mobile": "phone", "phone numbers": "phone",
    "email": "email", "email_address": "email", "email addresses": "email", "qqmail": "email",
    "username": "username", "usernames": "username",
    "dob": "dob", "date_of_birth": "dob", "birthdate": "dob", "dates of birth": "dob",
    "address": "address", "physical addresses": "address",
}
# Bookkeeping columns, not leaked data.
_IGNORED_FIELDS = {"id", "line", "source", "sources", "fields", "breach_date", "date"}

PII_FIELDS = {"name", "phone", "dob", "address", "ip", "gender", "country"}
_HASH_HEX = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|\$2[aby]\$.+)$", re.I)


def canonical_fields(names) -> list[str]:
    out: set[str] = set()
    for n in names or []:
        key = str(n).strip().lower()
        if not key or key in _IGNORED_FIELDS:
            continue
        out.add(_FIELD_ALIASES.get(key, key))
    return sorted(out)


def password_field_kind(value: str | None) -> str | None:
    """'password_hash' if `value` looks like a hash, 'password' otherwise —
    used only to classify; the value itself is discarded by the caller."""
    if not value:
        return None
    return "password_hash" if _HASH_HEX.match(str(value)) else "password"


# ── 4. Severity ─────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
OLD_LEAK_YEARS = 5


def is_stealer_source(source_name: str | None) -> bool:
    return "stealer" in (source_name or "").lower()


def parse_leak_date(value) -> datetime | None:
    """Accepts '2019', '2019-07', '2019-07-01' (and longer ISO strings)."""
    if not value:
        return None
    s = str(value).strip()
    for fmt, length in (("%Y-%m-%d", 10), ("%Y-%m", 7), ("%Y", 4)):
        try:
            return datetime.strptime(s[:length], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _target_domain(target: str, target_type: str) -> str:
    """The organization domain for the "email on the target's own domain"
    rule — only for domain targets. For an email target every match *is* the
    target's domain, which would make a plain hash always critical and the
    "high" band unreachable."""
    return target if target_type == "domain" else ""


def _email_on_domain(email: str | None, domain: str) -> bool:
    if not email or "@" not in email or not domain:
        return False
    host = email.rpartition("@")[2].lower()
    return host == domain or host.endswith("." + domain)


def compute_severity(*, source_name: str | None, leaked_fields, matched_field: str | None,
                     matched_value: str | None, target: str, target_type: str,
                     leak_date=None, now: datetime | None = None) -> str:
    """
    Precedence (first match wins):
      critical  Stealer Logs source (always — overrides everything else),
                a plaintext password, or (domain targets) an email on the
                target's own domain together with any password (plain or hashed)
      high      a password hash
      low       a leak older than OLD_LEAK_YEARS (for leaks without credentials)
      medium    an email together with personal data (name/phone/IP/...)
      low       everything else (email or username only)
    """
    if is_stealer_source(source_name):
        return "critical"
    fields = set(leaked_fields or [])
    if "password" in fields:
        return "critical"
    has_email = matched_field == "email" or "email" in fields
    if "password_hash" in fields:
        if matched_field == "email" and _email_on_domain(matched_value, _target_domain(target, target_type)):
            return "critical"
        return "high"
    when = parse_leak_date(leak_date)
    now = now or datetime.now(timezone.utc)
    if when and when < now - timedelta(days=365.25 * OLD_LEAK_YEARS):
        return "low"
    if has_email and fields & PII_FIELDS:
        return "medium"
    return "low"


def severity_counts(severities) -> dict:
    counts = {k: 0 for k in SEVERITY_ORDER}
    for s in severities:
        if s in counts:
            counts[s] += 1
    return counts


# ── 5. Fingerprint / dedupe ─────────────────────────────────────────────────

def record_fingerprint(source_name: str | None, matched_field: str | None,
                       matched_value: str | None, target: str) -> str:
    """Dedupe key = (source + matched field/value + monitored target). The
    provider is deliberately *not* part of it: the same breach reported by
    LeakCheck and Leak-Lookup is one alert, not two."""
    raw = "|".join((
        "record",
        (source_name or "unknown").strip().lower(),
        (matched_field or "").lower(),
        (matched_value or "").strip().lower(),
        (target or "").strip().lower(),
    ))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def record_to_event(record: dict, target: str, target_type: str) -> dict:
    """One normalized leak record → one storable alert event (masked)."""
    source_name = record.get("source_name") or "Unknown source"
    matched_field = record.get("matched_field") or target_type
    matched_value = record.get("matched_value") or target
    fields = canonical_fields(record.get("leaked_fields"))
    severity = compute_severity(
        source_name=source_name, leaked_fields=fields, matched_field=matched_field,
        matched_value=matched_value, target=target, target_type=target_type,
        leak_date=record.get("leak_date"),
    )
    masked = mask_value(matched_value, matched_field)
    return {
        "fingerprint": record_fingerprint(source_name, matched_field, matched_value, target),
        "source": record.get("provider") or "leakcheck",
        "severity": severity,
        "title": f"{source_name} — {masked}",
        "matched_field": matched_field,
        "leak_date": record.get("leak_date") or None,
        "leaked_fields": fields,
        # In-memory only (merge_events needs it) — never persisted or returned.
        "_matched_value": matched_value,
        "detail": {
            "provider": record.get("provider"),
            "source_name": source_name,
            "matched_field": matched_field,
            "matched_value_masked": masked,
            "leak_date": record.get("leak_date") or None,
            "leaked_fields": fields,
        },
    }


def merge_events(events: list[dict], target: str, target_type: str) -> list[dict]:
    """Collapse events sharing a fingerprint within one check run: union their
    leaked fields, keep the earliest-known date, and recompute severity."""
    merged: dict[str, dict] = {}
    order: list[str] = []
    for ev in events:
        fp = ev["fingerprint"]
        if fp not in merged:
            merged[fp] = ev
            order.append(fp)
            continue
        cur = merged[fp]
        if "leaked_fields" not in cur:
            continue  # non-record events (paste/github/actor) are already unique
        fields = sorted(set(cur["leaked_fields"]) | set(ev.get("leaked_fields") or []))
        cur["leaked_fields"] = cur["detail"]["leaked_fields"] = fields
        cur["leak_date"] = cur["detail"]["leak_date"] = cur.get("leak_date") or ev.get("leak_date")
        providers = {cur["detail"].get("provider"), ev["detail"].get("provider")} - {None}
        cur["detail"]["providers"] = sorted(providers)
        cur["severity"] = min(
            cur["severity"],
            compute_severity(
                source_name=cur["detail"]["source_name"], leaked_fields=fields,
                matched_field=cur["matched_field"], matched_value=cur.get("_matched_value"), target=target,
                target_type=target_type, leak_date=cur["leak_date"],
            ),
            key=lambda s: SEVERITY_ORDER.get(s, 9),
        )
    return [merged[fp] for fp in order]
