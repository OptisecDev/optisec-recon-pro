"""Context-aware (ABAC) authorization layered on top of web/auth.py's role checks.

Rules are data, not code. They are loaded from config/abac_rules.json
(override the path with ABAC_RULES_PATH). Each rule must have
id / roles / resource / conditions / effect / confirm; the file is validated
at load and any error makes every require_abac() dependency deny. "confirm"
is true for owner-approved rules and false for rules awaiting owner review;
it is recorded, not enforced. Evaluation:

  1. Rules match on role (or "*") and resource.
  2. A missing attribute can never allow: a matching deny rule that needs it
     denies outright, and a matching allow rule that needs it does not match.
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
  request_time    — now, as an aware datetime in the policy's IANA zone:
                    ABAC_TIMEZONE, else config "timezone", else Asia/Baghdad
                    (owner decision). Never the server's local zone: Render
                    runs in UTC. An invalid ABAC_TIMEZONE logs an ERROR and
                    falls back to Asia/Baghdad; an invalid config "timezone"
                    fails closed like any other config error (also ERROR).
  operation       — "read" for GET/HEAD, "action" for every other method
  route           — path template of the matched FastAPI route, e.g.
                    "/api/cve/drafts/{draft_id}/export" (never the raw URL)

Resource attributes come from per-endpoint providers passed to require_abac()
and are None (missing => deny) on endpoints that don't pass one:
  resource_severity — from a record, never from the request itself; see
                    resolve_resource_severity() / cve_severity_provider.
  scan_checks     — scan_authz.expand_checks() of the body's "scan_types"
  target_authorized — scan_authz.decide(...).ok for the body's "target"; see
                    scan_authz_provider.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, time
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from web import scan_authz
from web.auth import get_client_ip, get_current_user
from web.database import get_db

logger = logging.getLogger("auth.abac")

RULES_PATH_ENV = "ABAC_RULES_PATH"
TIMEZONE_ENV = "ABAC_TIMEZONE"
DEFAULT_TIMEZONE = "Asia/Baghdad"
DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "config" / "abac_rules.json"

PROVIDED_ATTRIBUTES = frozenset({"resource_severity", "scan_checks", "target_authorized"})
ATTRIBUTES = frozenset({"role", "ip_address", "request_time", "operation", "route"}) | PROVIDED_ATTRIBUTES
READ_METHODS = frozenset({"GET", "HEAD"})
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
    confirm: bool

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


def _parse_nonempty_list(value: Any) -> frozenset:
    if not isinstance(value, list) or not value:
        raise PolicyError("'subset_of' needs a non-empty list")
    return frozenset(value)


def _subset(actual: Any, allowed: frozenset) -> bool:
    if not isinstance(actual, (list, tuple, set, frozenset)) or not actual:
        return False
    return set(actual) <= allowed


def _ip(value: Any):
    return ipaddress.ip_address(str(value))


# op name -> (compile(value) -> compiled, required attr or None, test(actual, compiled, cond) -> bool)
_OPS: dict[str, tuple[Callable, Optional[str], Callable]] = {
    "eq": (lambda v: v, None,
           lambda a, v, c: (str(a).casefold() == str(v).casefold()) if c.case_insensitive else a == v),
    "in": (_parse_list, None,
           lambda a, v, c: (str(a).casefold() in {str(x).casefold() for x in v}) if c.case_insensitive else a in v),
    "not_in": (_parse_list, None,
               lambda a, v, c: (str(a).casefold() not in {str(x).casefold() for x in v}) if c.case_insensitive else a not in v),
    "subset_of": (_parse_nonempty_list, "scan_checks", lambda a, v, c: _subset(a, v)),
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


def _zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError) as exc:
        raise PolicyError(f"unknown timezone {name!r}") from exc


def _resolve_timezone(explicit: Optional[str], configured: Any) -> ZoneInfo:
    """Explicit argument > ABAC_TIMEZONE > config "timezone" > DEFAULT_TIMEZONE."""
    if explicit:
        return _zone(explicit)
    env_name = os.environ.get(TIMEZONE_ENV)
    if env_name:
        try:
            return _zone(env_name)
        except PolicyError:
            logger.error("Invalid %s=%r rejected; using %s instead", TIMEZONE_ENV, env_name, DEFAULT_TIMEZONE)
            return ZoneInfo(DEFAULT_TIMEZONE)
    if configured is None:
        return ZoneInfo(DEFAULT_TIMEZONE)
    if not isinstance(configured, str) or not configured:
        raise PolicyError("policy 'timezone' must be a non-empty IANA zone name")
    return _zone(configured)


def policy_from_dict(data: Mapping[str, Any], timezone: Optional[str] = None) -> Policy:
    if not isinstance(data, Mapping):
        raise PolicyError("policy must be an object")
    tz = _resolve_timezone(timezone, data.get("timezone"))

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
        conds = raw.get("conditions")
        if not isinstance(conds, list):
            raise PolicyError(f"rule {rid}: 'conditions' must be a list")
        confirm = raw.get("confirm")
        if not isinstance(confirm, bool):
            raise PolicyError(f"rule {rid}: 'confirm' must be true or false")
        rules.append(Rule(
            id=rid, roles=frozenset(roles), resource=resource, effect=effect, confirm=confirm,
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

    when = attrs.get("request_time")
    if isinstance(when, datetime):
        # Business hours are wall-clock times in policy.timezone, whatever zone
        # the caller's datetime is in. A naive datetime has no instant: deny.
        if when.utcoffset() is None:
            return Decision(False, None, "invalid attribute value: naive request_time")
        attrs = {**attrs, "request_time": when.astimezone(policy.timezone)}

    applicable = [r for r in policy.rules if r.targets(role, resource)]
    allow_hit: Optional[Rule] = None
    missing_hit: Optional[Decision] = None
    for rule in applicable:
        missing = [c.attr for c in rule.conditions if _is_missing(attrs.get(c.attr))]
        if missing:
            reason = Decision(False, rule.id, f"missing attribute: {missing[0]}")
            if rule.effect == "deny":
                return reason
            missing_hit = missing_hit or reason
            continue
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
    return missing_hit or Decision(False, None, "no matching rule (default deny)")


# ── FastAPI integration ──────────────────────────────────────────────────────

async def _json_body(request: Request) -> Optional[dict]:
    if "application/json" not in request.headers.get("content-type", ""):
        return None
    try:
        body = await request.json()  # cached by Starlette; the handler can still read it
    except Exception:  # noqa: BLE001 — malformed body => attributes missing => deny
        return None
    return body if isinstance(body, dict) else None


async def _request_value(request: Request, name: str) -> Any:
    """Query parameter `name`, else the top-level JSON body field `name`, else None."""
    value = request.query_params.get(name)
    if value is not None:
        return value
    if request.method in ("POST", "PUT", "PATCH"):
        body = await _json_body(request)
        if body is not None:
            return body.get(name)
    return None


def _positive_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if n > 0 and str(n) == str(value).strip() else None


async def finding_severity_for_user(db: AsyncSession, finding_id: int, user: Any) -> Optional[str]:
    """Finding.severity for one of the user's own findings, via the CVE router's
    get_finding_for_user (same Scan.user_id ownership check). None if not found."""
    from web.routers.cve_submission import get_finding_for_user

    finding = await get_finding_for_user(db, finding_id, user.id)
    return finding.severity if finding is not None else None


FindingLookup = Callable[[AsyncSession, int, Any], Awaitable[Optional[str]]]
# (request, user, db) -> {attribute: value}; keys must be in PROVIDED_ATTRIBUTES
AttributeProvider = Callable[[Request, Any, AsyncSession], Awaitable[Mapping[str, Any]]]


async def resolve_resource_severity(
    request: Request,
    user: Any,
    db: AsyncSession,
    finding_lookup: Optional[FindingLookup] = None,
) -> Optional[str]:
    """Severity of the resource a CVE pipeline request acts on. None means missing (deny).

    1. Target: "finding_id" (query or JSON body; POST /api/cve/draft takes it in
       the body). Severity is Finding.severity of the caller's own finding. The
       Target model has no severity column, so the finding is the target record.
       A finding_id that is present but malformed or not the caller's gives None;
       it never falls through to step 2.
    2. CVE: "draft_id" path parameter or "cve_id" query parameter. CveDraft has
       cvss_score, but the codebase has no CVSS -> severity mapping for this
       purpose, so this returns None until an approved mapping is added here.
    """
    raw_finding = await _request_value(request, "finding_id")
    if raw_finding is not None:
        finding_id = _positive_int(raw_finding)
        if finding_id is None:
            return None
        return await (finding_lookup or finding_severity_for_user)(db, finding_id, user)
    # Step 2 (draft_id / cve_id): no verified CVSS -> severity mapping, so None.
    return None


async def cve_severity_provider(request: Request, user: Any, db: AsyncSession) -> dict:
    """Provider for CVE pipeline routes: require_abac("cve_pipeline", providers=(cve_severity_provider,))."""
    return {"resource_severity": await resolve_resource_severity(request, user, db)}


ScopesLoader = Callable[[AsyncSession, Any], Awaitable[list]]


async def scan_authz_provider(
    request: Request,
    user: Any,
    db: AsyncSession,
    scopes_loader: Optional[ScopesLoader] = None,
) -> dict:
    """Provider for POST /api/scan (web/app.py:run_scan), which takes a JSON body
    {"target": str, "scan_types": [str]}.

    scan_checks is scan_authz.expand_checks(scan_types), never the raw list: an
    empty or missing scan_types means every module (SQLi included), and if the
    expansion fails scan_checks stays missing, which denies. target_authorized is scan_authz.decide(target, checks, scopes).ok,
    where scopes are the user's verified domains (load_verified_scopes by default).
    That is taken at face value, like preview_authorization(); run_scan still calls
    check_scan_authorization(), which re-checks DNS, so this can only narrow.
    Malformed input or any error in the authorization path leaves the attribute
    missing, which denies."""
    out = {"scan_checks": None, "target_authorized": None}
    body = await _json_body(request)
    if body is None:
        return out
    target, scan_types = body.get("target"), body.get("scan_types", [])
    if not isinstance(scan_types, list) or not all(isinstance(t, str) for t in scan_types):
        return out
    try:
        checks = scan_authz.expand_checks(scan_types)
    except Exception as exc:  # noqa: BLE001 — no expanded list => scan_checks missing => deny
        logger.warning("ABAC scan check expansion error: %s", type(exc).__name__)
        return out
    out["scan_checks"] = checks
    if not isinstance(target, str) or not target.strip():
        return out
    try:
        if scopes_loader is None:
            from web.domain_verification import load_verified_scopes as scopes_loader
        scopes = await scopes_loader(db, user)
        out["target_authorized"] = bool(scan_authz.decide(target.strip(), checks, scopes).ok)
    except Exception as exc:  # noqa: BLE001 — fail closed
        logger.warning("ABAC scan authorization error: %s", type(exc).__name__)
    return out


async def build_attributes(
    request: Request,
    user: Any,
    policy: Policy,
    now: Optional[Callable[[], datetime]] = None,
    db: Optional[AsyncSession] = None,
    providers: tuple = (),
) -> dict:
    ip = get_client_ip(request)
    current = now() if now else datetime.now(policy.timezone)
    if current.tzinfo is None:
        raise ValueError("clock must return an aware datetime")
    attrs = dict.fromkeys(PROVIDED_ATTRIBUTES)
    for provider in providers:
        provided = await provider(request, user, db)
        unknown = set(provided) - PROVIDED_ATTRIBUTES
        if unknown:
            raise ValueError(f"provider returned unknown attribute(s): {sorted(unknown)}")
        attrs.update(provided)
    return {
        **attrs,
        "role": getattr(user, "role", None),
        "ip_address": None if ip in (None, "", "unknown") else ip,
        "request_time": current.astimezone(policy.timezone),
        "operation": "read" if request.method.upper() in READ_METHODS else "action",
        "route": getattr(request.scope.get("route"), "path", None),
    }


async def abac_user(request: Request, db: AsyncSession = Depends(get_db)):
    """Resolve the authenticated user the same way the routers' _user() helpers do."""
    return await get_current_user(request, db)


def require_abac(
    resource: str,
    policy_provider: Callable[[], Policy] = get_policy,
    clock: Optional[Callable[[], datetime]] = None,
    providers: tuple = (),
):
    """FastAPI dependency factory: Depends(require_abac("ngfw_rules")).

    `providers` supply resource attributes for this endpoint, e.g.
    providers=(cve_severity_provider,) on CVE pipeline routes.

    Returns the authenticated user on allow; raises 403 on deny. Apply it
    per endpoint, next to (not instead of) the existing role checks.
    """

    async def dependency(request: Request, user=Depends(abac_user), db: AsyncSession = Depends(get_db)):
        try:
            policy = policy_provider()
            attrs = await build_attributes(request, user, policy, now=clock, db=db,
                                           providers=providers)
            decision = evaluate(policy, resource, attrs)
        except PolicyError as exc:
            logger.error("ABAC evaluation rejected for %s: invalid policy config: %s", resource, exc)
            decision = Decision(False, None, "invalid policy config")
        except Exception as exc:  # noqa: BLE001 — any failure fails closed
            logger.warning("ABAC evaluation error for %s: %s", resource, type(exc).__name__)
            decision = Decision(False, None, "evaluation error")
        if not decision.allowed:
            logger.info("ABAC deny resource=%s user_id=%s rule=%s reason=%s",
                        resource, getattr(user, "id", None), decision.rule_id, decision.reason)
            raise HTTPException(status_code=403, detail="Access denied by context policy")
        return user

    return dependency
