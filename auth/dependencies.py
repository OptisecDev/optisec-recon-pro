"""Context-aware (ABAC) authorization layered on top of web/auth.py's role checks.

Rules are data, not code. They are loaded from config/abac_rules.json
(override the path with ABAC_RULES_PATH). Each rule has
id / roles / resource / conditions / effect. Evaluation:

  1. Rules match on role (or "*") and resource.
  2. If a matching rule references an attribute that is missing, deny.
  3. Any matching deny whose conditions all hold wins (deny-overrides).
  4. Otherwise any matching allow whose conditions all hold allows.
  5. Otherwise deny (default).

This module never replaces web.auth.require_roles / require_admin /
require_analyst_or_admin. An endpoint that adopts require_abac() keeps its
existing role check, so ABAC can only narrow access, never widen it.

Attributes:
  role            — user.role
  ip_address      — web.auth.get_client_ip(request), the trusted-proxy-aware
                    resolver. Raw X-Forwarded-For is never read here.
  request_time    — now, in the configured IANA timezone (config "timezone",
                    overridable by ABAC_TIMEZONE)
  target_severity — query parameter or JSON body field "target_severity"
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, time
from pathlib import Path
from typing import Any, Callable, Mapping, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from web.auth import get_client_ip, get_current_user
from web.database import get_db

logger = logging.getLogger("auth.abac")

RULES_PATH_ENV = "ABAC_RULES_PATH"
TIMEZONE_ENV = "ABAC_TIMEZONE"
DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "config" / "abac_rules.json"

ATTRIBUTES = frozenset({"role", "ip_address", "request_time", "target_severity"})
EFFECTS = frozenset({"allow", "deny"})
_DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


class PolicyError(ValueError):
    """The ABAC configuration is invalid. Loading fails closed."""


# ── Policy model ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Condition:
    attr: str
    op: str
    value: Any
    case_insensitive: bool = False


@dataclass(frozen=True)
class Rule:
    id: str
    roles: frozenset
    resource: str
    conditions: tuple
    effect: str

    def targets(self, role: Optional[str], resource: str) -> bool:
        return self.resource == resource and ("*" in self.roles or (role is not None and role in self.roles))


@dataclass(frozen=True)
class Policy:
    rules: tuple
    timezone: ZoneInfo
    params: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    rule_id: Optional[str]
    reason: str


# ── Condition operators ──────────────────────────────────────────────────────

def _parse_hhmm(value: str) -> time:
    try:
        hh, mm = str(value).split(":")
        return time(int(hh), int(mm))
    except (ValueError, TypeError) as exc:
        raise PolicyError(f"invalid time {value!r}, expected HH:MM") from exc


def _parse_networks(value: Any) -> tuple:
    if not isinstance(value, list) or not value:
        raise PolicyError("network list must be a non-empty list")
    try:
        return tuple(ipaddress.ip_network(n, strict=False) for n in value)
    except ValueError as exc:
        raise PolicyError(f"invalid network: {exc}") from exc


def _parse_hours(value: Any) -> dict:
    if not isinstance(value, dict) or "start" not in value or "end" not in value:
        raise PolicyError("business hours need 'start' and 'end'")
    days = value.get("days", list(_DAYS))
    if not isinstance(days, list) or not days or any(d not in _DAYS for d in days):
        raise PolicyError(f"business hours 'days' must be a non-empty subset of {_DAYS}")
    start, end = _parse_hhmm(value["start"]), _parse_hhmm(value["end"])
    if start == end:
        raise PolicyError("business hours start and end must differ")
    return {"start": start, "end": end, "days": frozenset(days)}


def _within_hours(now: datetime, hours: dict) -> bool:
    t = now.time().replace(tzinfo=None)
    start, end = hours["start"], hours["end"]
    if start < end:
        in_window, day = start <= t < end, now.weekday()
    else:  # overnight window, e.g. 22:00–06:00; early-morning part belongs to the previous day
        in_window = t >= start or t < end
        day = now.weekday() if t >= start else (now.weekday() - 1) % 7
    return in_window and _DAYS[day] in hours["days"]


def _parse_list(value: Any) -> list:
    if not isinstance(value, list):
        raise PolicyError("'in' needs a list")
    return value


def _ip(value: Any):
    return ipaddress.ip_address(str(value))


# op name -> (compile(value) -> compiled, required attr or None, test(actual, compiled, cond) -> bool)
_OPS: dict[str, tuple[Callable, Optional[str], Callable]] = {
    "eq": (lambda v: v, None,
           lambda a, v, c: (str(a).casefold() == str(v).casefold()) if c.case_insensitive else a == v),
    "in": (_parse_list, None,
           lambda a, v, c: (str(a).casefold() in {str(x).casefold() for x in v}) if c.case_insensitive else a in v),
    "in_networks": (_parse_networks, "ip_address", lambda a, nets, c: any(_ip(a) in n for n in nets)),
    "not_in_networks": (_parse_networks, "ip_address", lambda a, nets, c: not any(_ip(a) in n for n in nets)),
    "within_hours": (_parse_hours, "request_time", lambda a, h, c: _within_hours(a, h)),
    "outside_hours": (_parse_hours, "request_time", lambda a, h, c: not _within_hours(a, h)),
}


# ── Loading ──────────────────────────────────────────────────────────────────

def _resolve_param(value: Any, params: Mapping[str, Any]) -> Any:
    if isinstance(value, str) and value.startswith("$"):
        name = value[1:]
        if name not in params:
            raise PolicyError(f"unknown parameter reference {value!r}")
        return params[name]
    return value


def _build_condition(raw: Any, params: Mapping[str, Any], rule_id: str) -> Condition:
    if not isinstance(raw, dict):
        raise PolicyError(f"rule {rule_id}: condition must be an object")
    attr, op = raw.get("attr"), raw.get("op")
    if attr not in ATTRIBUTES:
        raise PolicyError(f"rule {rule_id}: unknown attribute {attr!r}")
    if op not in _OPS:
        raise PolicyError(f"rule {rule_id}: unknown operator {op!r}")
    compile_value, required_attr, _ = _OPS[op]
    if required_attr and attr != required_attr:
        raise PolicyError(f"rule {rule_id}: operator {op!r} applies only to {required_attr!r}")
    if "value" not in raw:
        raise PolicyError(f"rule {rule_id}: condition missing 'value'")
    value = compile_value(_resolve_param(raw["value"], params))
    return Condition(attr=attr, op=op, value=value, case_insensitive=bool(raw.get("case_insensitive", False)))


def policy_from_dict(data: Mapping[str, Any], timezone: Optional[str] = None) -> Policy:
    if not isinstance(data, Mapping):
        raise PolicyError("policy must be an object")
    tz_name = timezone or os.environ.get(TIMEZONE_ENV) or data.get("timezone")
    if not tz_name:
        raise PolicyError("policy timezone is not configured")
    try:
        tz = ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise PolicyError(f"unknown timezone {tz_name!r}") from exc

    params = data.get("params", {}) or {}
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        raise PolicyError("'rules' must be a list")

    rules, seen = [], set()
    for raw in raw_rules:
        if not isinstance(raw, dict):
            raise PolicyError("rule must be an object")
        rid = raw.get("id")
        if not isinstance(rid, str) or not rid or rid in seen:
            raise PolicyError(f"rule id missing or duplicated: {rid!r}")
        seen.add(rid)
        roles = raw.get("roles")
        if not isinstance(roles, list) or not roles or not all(isinstance(r, str) and r for r in roles):
            raise PolicyError(f"rule {rid}: 'roles' must be a non-empty list of strings")
        resource = raw.get("resource")
        if not isinstance(resource, str) or not resource:
            raise PolicyError(f"rule {rid}: 'resource' must be a non-empty string")
        effect = raw.get("effect")
        if effect not in EFFECTS:
            raise PolicyError(f"rule {rid}: 'effect' must be one of {sorted(EFFECTS)}")
        conds = raw.get("conditions", [])
        if not isinstance(conds, list):
            raise PolicyError(f"rule {rid}: 'conditions' must be a list")
        rules.append(Rule(
            id=rid, roles=frozenset(roles), resource=resource, effect=effect,
            conditions=tuple(_build_condition(c, params, rid) for c in conds),
        ))
    return Policy(rules=tuple(rules), timezone=tz, params=params)


def load_policy(path: Optional[os.PathLike | str] = None) -> Policy:
    path = Path(path or os.environ.get(RULES_PATH_ENV) or DEFAULT_RULES_PATH)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"cannot load ABAC rules from {path.name}: {type(exc).__name__}") from exc
    return policy_from_dict(data)


_cached_policy: Optional[Policy] = None


def get_policy() -> Policy:
    global _cached_policy
    if _cached_policy is None:
        _cached_policy = load_policy()
    return _cached_policy


def reset_policy_cache() -> None:
    global _cached_policy
    _cached_policy = None


# ── Evaluation ───────────────────────────────────────────────────────────────

def _is_missing(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _holds(cond: Condition, attrs: Mapping[str, Any]) -> bool:
    _, _, test = _OPS[cond.op]
    return bool(test(attrs[cond.attr], cond.value, cond))


def evaluate(policy: Policy, resource: str, attrs: Mapping[str, Any]) -> Decision:
    """Pure decision function. It does no I/O and never raises on bad input; it denies instead."""
    role = attrs.get("role")
    if _is_missing(role):
        return Decision(False, None, "missing attribute: role")

    applicable = [r for r in policy.rules if r.targets(role, resource)]
    allow_hit: Optional[Rule] = None
    for rule in applicable:
        missing = [c.attr for c in rule.conditions if _is_missing(attrs.get(c.attr))]
        if missing:
            return Decision(False, rule.id, f"missing attribute: {missing[0]}")
        try:
            matched = all(_holds(c, attrs) for c in rule.conditions)
        except (ValueError, TypeError, AttributeError):
            return Decision(False, rule.id, "invalid attribute value")
        if not matched:
            continue
        if rule.effect == "deny":
            return Decision(False, rule.id, "denied by rule")
        if allow_hit is None:
            allow_hit = rule
    if allow_hit is not None:
        return Decision(True, allow_hit.id, "allowed by rule")
    return Decision(False, None, "no matching rule (default deny)")


# ── FastAPI integration ──────────────────────────────────────────────────────

async def _target_severity_from_request(request: Request) -> Optional[str]:
    value = request.query_params.get("target_severity")
    if value:
        return value
    if request.method in ("POST", "PUT", "PATCH") and "application/json" in request.headers.get("content-type", ""):
        try:
            body = await request.json()  # Starlette caches the body; the handler can still read it
        except Exception:  # noqa: BLE001 — malformed body => attribute missing => deny
            return None
        if isinstance(body, dict) and isinstance(body.get("target_severity"), str):
            return body["target_severity"]
    return None


async def build_attributes(
    request: Request,
    user: Any,
    policy: Policy,
    now: Optional[Callable[[], datetime]] = None,
) -> dict:
    ip = get_client_ip(request)
    current = now() if now else datetime.now(policy.timezone)
    if current.tzinfo is None:
        raise ValueError("clock must return an aware datetime")
    return {
        "role": getattr(user, "role", None),
        "ip_address": None if ip in (None, "", "unknown") else ip,
        "request_time": current.astimezone(policy.timezone),
        "target_severity": await _target_severity_from_request(request),
    }


async def abac_user(request: Request, db: AsyncSession = Depends(get_db)):
    """Resolve the authenticated user the same way the routers' _user() helpers do."""
    return await get_current_user(request, db)


def require_abac(
    resource: str,
    policy_provider: Callable[[], Policy] = get_policy,
    clock: Optional[Callable[[], datetime]] = None,
):
    """FastAPI dependency factory: Depends(require_abac("ngfw_rules")).

    Returns the authenticated user on allow; raises 403 on deny. Apply it
    per endpoint, next to (not instead of) the existing role checks.
    """

    async def dependency(request: Request, user=Depends(abac_user)):
        try:
            policy = policy_provider()
            attrs = await build_attributes(request, user, policy, now=clock)
            decision = evaluate(policy, resource, attrs)
        except Exception as exc:  # noqa: BLE001 — any failure fails closed
            logger.warning("ABAC evaluation error for %s: %s", resource, type(exc).__name__)
            decision = Decision(False, None, "evaluation error")
        if not decision.allowed:
            logger.info("ABAC deny resource=%s user_id=%s rule=%s reason=%s",
                        resource, getattr(user, "id", None), decision.rule_id, decision.reason)
            raise HTTPException(status_code=403, detail="Access denied by context policy")
        return user

    return dependency
