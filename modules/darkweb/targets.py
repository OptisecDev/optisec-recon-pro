"""
Dark Web Monitoring — target normalization + validation.

Every monitored target is normalized and validated here before it is stored
or queried. A bare word like "tp-link" used to be stored as a "domain" target,
and LeakCheck then auto-detected it as a *username* and returned 26 unrelated
leaks. A domain target now has to be a real hostname with a TLD, and every
rejection comes with a bilingual message plus a suggested fix where one is
obvious ("tp-link" → "tp-link.com").

The browser applies the same rules (web/templates/darkweb.html,
`dwValidateTarget`) so the user gets instant feedback, but this module is the
authority: the API re-validates every write.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

TARGET_TYPES = ("domain", "email", "username")

# One DNS label: 1-63 chars, alnum at both ends, hyphens allowed inside.
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
# TLD: alphabetic (2-63) or an IDN punycode TLD (xn--...).
_TLD = r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})"
_RE_DOMAIN = re.compile(rf"^(?:{_LABEL}\.)+{_TLD}$")
_RE_EMAIL_LOCAL = re.compile(r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$")
_RE_USERNAME = re.compile(r"^[a-z0-9._-]{3,64}$")
_RE_BARE_LABEL = re.compile(rf"^{_LABEL}$")
_RE_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://")


@dataclass
class TargetValidation:
    ok: bool
    target: str
    target_type: str | None
    error_en: str | None = None
    error_ar: str | None = None
    suggestion: str | None = None
    extra: dict = field(default_factory=dict)

    def error_payload(self) -> dict:
        """JSON body for a 400/422 response — bilingual, with the suggestion."""
        return {
            "error": "invalid_target",
            "message_en": self.error_en,
            "message_ar": self.error_ar,
            "suggestion": self.suggestion,
            "normalized": self.target,
            "target_type": self.target_type,
        }


def normalize_target(raw: str | None) -> str:
    """Lowercase, strip whitespace (everywhere), drop a URL scheme, any
    userinfo/path/query/fragment/port, a leading "www." and a trailing dot.
    Emails keep their local part untouched apart from lowercasing."""
    value = re.sub(r"\s+", "", (raw or "")).lower()
    if not value:
        return ""
    if "@" in value and not _RE_SCHEME.match(value) and "/" not in value:
        local, _, host = value.rpartition("@")
        host = host.rstrip(".")
        return f"{local}@{host}"
    value = _RE_SCHEME.sub("", value)
    value = re.split(r"[/?#]", value, maxsplit=1)[0]
    value = value.rsplit("@", 1)[-1]          # drop user:pass@ in a URL
    value = value.split(":", 1)[0]            # drop :port
    value = value.rstrip(".")
    if value.startswith("www."):
        value = value[4:]
    return value


def is_valid_domain(value: str) -> bool:
    return len(value) <= 253 and bool(_RE_DOMAIN.match(value))


def _suggest_domain(value: str) -> str | None:
    """Best-effort fix for an almost-domain: "tp-link" → "tp-link.com",
    "tp_link.com" → "tp-link.com", "tp-link..com" → "tp-link.com"."""
    candidate = re.sub(r"[^a-z0-9.-]", "-", value)
    candidate = re.sub(r"\.{2,}", ".", candidate).strip(".-")
    candidate = re.sub(r"-*\.-*", ".", candidate)
    if not candidate:
        return None
    if is_valid_domain(candidate):
        return candidate if candidate != value else None
    if _RE_BARE_LABEL.match(candidate):
        return f"{candidate}.com"
    return None


def _invalid(target: str, target_type: str, en: str, ar: str, suggestion: str | None) -> TargetValidation:
    if suggestion:
        en = f"{en} Did you mean {suggestion}?"
        ar = f"{ar} هل تقصد {suggestion}؟"
    return TargetValidation(False, target, target_type, en, ar, suggestion)


def validate_target(raw: str | None, target_type: str | None = None) -> TargetValidation:
    """
    Normalize and validate a monitoring target.

    `target_type` may be forced to "domain" / "email" / "username"; when
    omitted it is inferred — anything containing "@" is an email, everything
    else is a domain. A username is never inferred: a bare word is far more
    likely to be a mistyped domain (the "tp-link" case), so it must be asked
    for explicitly.
    """
    target = normalize_target(raw)
    if target_type is not None and target_type not in TARGET_TYPES:
        return TargetValidation(
            False, target, None,
            f"Unknown target type '{target_type}'. Use domain, email or username.",
            f"نوع الهدف '{target_type}' غير معروف. استخدم domain أو email أو username.",
        )
    if not target:
        return TargetValidation(False, "", target_type, "Target is required.", "الهدف مطلوب.")

    inferred = target_type or ("email" if "@" in target else "domain")

    if inferred == "email":
        local, sep, host = target.rpartition("@")
        if not sep or not local or not _RE_EMAIL_LOCAL.match(local) or ".." in local:
            return _invalid(target, "email", "Invalid email address.", "عنوان بريد إلكتروني غير صالح.", None)
        if not is_valid_domain(host):
            fixed = _suggest_domain(host)
            return _invalid(
                target, "email",
                f"Invalid email domain '{host}' — it needs a TLD (e.g. .com).",
                f"نطاق البريد '{host}' غير صالح — يجب أن يحتوي على امتداد (مثل .com).",
                f"{local}@{fixed}" if fixed else None,
            )
        return TargetValidation(True, target, "email")

    if inferred == "username":
        if not _RE_USERNAME.match(target):
            return _invalid(
                target, "username",
                "Invalid username — 3-64 characters: letters, digits, dot, dash, underscore.",
                "اسم مستخدم غير صالح — من 3 إلى 64 حرفاً: أحرف وأرقام ونقطة وشرطة وشرطة سفلية.",
                None,
            )
        return TargetValidation(True, target, "username")

    if not is_valid_domain(target):
        return _invalid(
            target, "domain",
            f"'{target}' is not a valid domain — a domain needs a TLD (e.g. example.com).",
            f"'{target}' ليس نطاقاً صالحاً — يجب أن يحتوي النطاق على امتداد (مثل example.com).",
            _suggest_domain(target),
        )
    return TargetValidation(True, target, "domain")


# ── Masking ─────────────────────────────────────────────────────────────────
# Used server-side before anything leak-derived is stored or sent to the
# browser — the raw matched value never leaves the backend.

def mask_value(value: str | None, kind: str | None = None) -> str:
    """a***@domain.com for emails, j***e for usernames; domains are the
    monitored target itself and are returned as-is."""
    value = (value or "").strip()
    if not value:
        return ""
    if kind == "domain":
        return value
    if "@" in value:
        local, _, host = value.rpartition("@")
        return f"{local[:1]}***@{host}"
    if len(value) <= 2:
        return value[:1] + "***"
    return f"{value[:1]}***{value[-1:]}"
