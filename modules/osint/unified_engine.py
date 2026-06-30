"""
Unified OSINT Engine v5.0
Parallel subprocess wrappers for Amass, theHarvester, Maigret, Holehe.

External tool installation notes:
  - Amass   : Go binary — `go install github.com/owasp-amass/amass/v4/...@master`
               or `apt install amass` / `brew install amass`
  - theHarvester : `pip install theHarvester` or `pipx install theHarvester`
  - Maigret  : `pip install maigret`
  - Holehe   : `pip install holehe`
"""

import asyncio
import json
import logging
import re
import shutil
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

logger = logging.getLogger("osint.unified")

# ── Per-tool timeouts (seconds) ───────────────────────────────────────────────
_TOOL_TIMEOUTS: dict[str, int] = {
    "amass":        60,
    "theharvester": 150,
    "maigret":      60,
    "holehe":       45,
}

# ── Binary resolution: system PATH + venv bin + ~/bin ────────────────────────
# - pip tools (maigret, holehe, theHarvester) live in the venv bin dir
# - Go/system binaries (amass) may live in ~/bin which isn't always in PATH
_VENV_BIN  = Path(sys.executable).parent
_USER_BIN  = Path.home() / "bin"
_EXTRA_DIRS = [_VENV_BIN, _USER_BIN]


def _find_binary(name: str) -> str | None:
    """Return full path to binary: system PATH → venv bin → ~/bin."""
    found = shutil.which(name)
    if found:
        return found
    for d in _EXTRA_DIRS:
        p = d / name
        if p.is_file():
            return str(p)
    return None

# ── Simple in-memory rate limiter ─────────────────────────────────────────────
_rate_store: dict[str, list[float]] = defaultdict(list)
_RATE_WINDOW = 60   # seconds
_RATE_MAX    = 10   # max requests per window per key


def _check_rate(key: str) -> bool:
    """Return True if the request is allowed, False if rate-limited."""
    now = time.monotonic()
    hits = [t for t in _rate_store[key] if now - t < _RATE_WINDOW]
    _rate_store[key] = hits
    if len(hits) >= _RATE_MAX:
        return False
    hits.append(now)
    return True


# ── Target-type auto-detection ────────────────────────────────────────────────
_RE_IP     = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_RE_EMAIL  = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
_RE_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def detect_target_type(target: str) -> str:
    """Infer target type from its format."""
    t = target.strip()
    if _RE_IP.match(t):
        return "ip"
    if _RE_EMAIL.match(t):
        return "email"
    if _RE_DOMAIN.match(t):
        return "domain"
    return "username"


# ── Generic async subprocess runner ──────────────────────────────────────────

async def _run_tool(
    name: str,
    cmd: list[str],
    timeout: int,
    parse_fn,
) -> dict[str, Any]:
    """
    Run an external command, capture stdout/stderr, parse output.
    Never raises — errors are captured in the returned dict.
    """
    binary = _find_binary(cmd[0])
    if not binary:
        logger.debug("[%s] binary not found: %s", name, cmd[0])
        return {
            "source": name,
            "available": False,
            "error": f"{cmd[0]} not installed or not in PATH/venv",
            "results": [],
        }
    cmd = [binary] + cmd[1:]

    logger.info("[%s] running: %s", name, " ".join(cmd))
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.communicate()
            except Exception:
                pass
            logger.warning("[%s] timed out after %ds", name, timeout)
            return {
                "source": name,
                "available": True,
                "error": f"timed out after {timeout}s",
                "results": [],
            }

        out = stdout.decode(errors="replace")
        err = stderr.decode(errors="replace")
        if proc.returncode not in (0, 1, None):
            logger.warning("[%s] exit code %d: %s", name, proc.returncode, err[:300])

        parsed = parse_fn(out)
        logger.info("[%s] parsed %d results", name, len(parsed))
        return {
            "source": name,
            "available": True,
            "results": parsed,
            "stderr": (err[:500] if err.strip() else None),
        }

    except Exception as exc:
        logger.error("[%s] unexpected error: %s", name, exc)
        return {
            "source": name,
            "available": True,
            "error": str(exc),
            "results": [],
        }


# ── Amass ─────────────────────────────────────────────────────────────────────
# NOTE: Amass is a Go binary — not installable via pip.
# Install: go install github.com/owasp-amass/amass/v4/...@master
# or: apt install amass | brew install amass

def _parse_amass(out: str) -> list[dict]:
    results = []
    seen: set[str] = set()
    for line in out.splitlines():
        sub = line.strip()
        if sub and sub not in seen:
            seen.add(sub)
            results.append({"type": "subdomain", "value": sub})
    return results


async def _run_amass(domain: str) -> dict:
    return await _run_tool(
        "amass",
        # -passive avoids active DNS brute-force; -timeout in minutes
        ["amass", "enum", "-passive", "-d", domain, "-timeout", "1"],
        _TOOL_TIMEOUTS["amass"],
        _parse_amass,
    )


# ── theHarvester ──────────────────────────────────────────────────────────────
# Install: pip install theHarvester

def _parse_theharvester(out: str) -> list[dict]:
    results = []
    section: str | None = None
    seen: set[str] = set()

    for line in out.splitlines():
        stripped = line.strip()
        low = stripped.lower()

        if "emails found" in low or "email addresses" in low:
            section = "email"
            continue
        if "hosts found" in low or "interesting urls" in low:
            section = "host"
            continue
        if stripped.startswith("[*]") or not stripped:
            section = None
            continue

        if section == "email" and "@" in stripped and stripped not in seen:
            seen.add(stripped)
            results.append({"type": "email", "value": stripped})
        elif section == "host" and "." in stripped and stripped not in seen:
            seen.add(stripped)
            results.append({"type": "host", "value": stripped})

    return results


async def _run_theharvester(target: str, target_type: str) -> dict:
    domain = target.split("@")[-1] if target_type == "email" else target
    # Use only free sources that don't require API keys
    return await _run_tool(
        "theHarvester",
        ["theHarvester", "-d", domain, "-b", "all", "-l", "100"],
        _TOOL_TIMEOUTS["theharvester"],
        _parse_theharvester,
    )


# ── Maigret ───────────────────────────────────────────────────────────────────
# Install: pip install maigret

def _parse_maigret(out: str) -> list[dict]:
    results = []
    # Try JSON first
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            for site, info in data.items():
                if not isinstance(info, dict):
                    continue
                status = info.get("status", {})
                status_id = (
                    status.get("id") if isinstance(status, dict)
                    else str(status)
                )
                if status_id in ("CLAIMED", "found"):
                    results.append({
                        "type": "profile",
                        "platform": site,
                        "url": info.get("url_user", ""),
                        "status": "found",
                    })
        return results
    except (json.JSONDecodeError, AttributeError):
        pass

    # Fallback: text output
    for line in out.splitlines():
        if "[+]" in line:
            parts = line.split()
            url = next((p for p in parts if p.startswith("http")), "")
            results.append({"type": "profile", "url": url, "raw": line.strip(), "status": "found"})
    return results


async def _run_maigret(username: str) -> dict:
    return await _run_tool(
        "maigret",
        ["maigret", username, "--timeout", "15", "--no-color"],
        _TOOL_TIMEOUTS["maigret"],
        _parse_maigret,
    )


# ── Holehe ────────────────────────────────────────────────────────────────────
# Install: pip install holehe

def _parse_holehe(out: str) -> list[dict]:
    results = []
    # Try JSON
    try:
        data = json.loads(out)
        if isinstance(data, list):
            for item in data:
                if item.get("exists"):
                    results.append({
                        "type": "account",
                        "platform": item.get("name", ""),
                        "domain": item.get("domain", ""),
                        "status": "registered",
                    })
        return results
    except (json.JSONDecodeError, AttributeError):
        pass

    # Fallback: text output (lines starting with [+])
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("[+]") or "✔" in stripped:
            results.append({"type": "account", "raw": stripped, "status": "registered"})
    return results


async def _run_holehe(email: str) -> dict:
    return await _run_tool(
        "holehe",
        ["holehe", email],
        _TOOL_TIMEOUTS["holehe"],
        _parse_holehe,
    )


# ── Unified dispatcher ────────────────────────────────────────────────────────

async def search_unified(
    target: str,
    target_type: str,
    rate_key: str = "global",
) -> dict[str, Any]:
    """
    Run all applicable OSINT tools in parallel for the given target.

    Args:
        target:      The target string (domain, email, username, or IP).
        target_type: One of "domain", "email", "username", "ip", "auto".
        rate_key:    Opaque key for rate-limiting (e.g. "user:42").

    Returns:
        Aggregated JSON dict with per-source results, total count, elapsed time.
    """
    if not _check_rate(rate_key):
        return {
            "error": "rate_limited",
            "message": f"Max {_RATE_MAX} requests per {_RATE_WINDOW}s exceeded",
            "target": target,
        }

    if target_type == "auto":
        target_type = detect_target_type(target)

    logger.info("unified_search start target=%r type=%s key=%s", target, target_type, rate_key)
    t0 = time.monotonic()

    tasks: list[asyncio.coroutines] = []
    labels: list[str] = []

    if target_type == "domain":
        tasks += [_run_amass(target), _run_theharvester(target, target_type)]
        labels += ["amass", "theharvester"]

    elif target_type == "email":
        tasks += [_run_holehe(target), _run_theharvester(target, target_type)]
        labels += ["holehe", "theharvester"]

    elif target_type == "username":
        tasks += [_run_maigret(target)]
        labels += ["maigret"]

    elif target_type == "ip":
        tasks += [_run_theharvester(target, target_type)]
        labels += ["theharvester"]

    raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    by_source: list[dict] = []
    total = 0
    for label, raw in zip(labels, raw_results):
        if isinstance(raw, Exception):
            entry: dict = {"source": label, "error": str(raw), "results": []}
        else:
            entry = raw
        total += len(entry.get("results") or [])
        by_source.append(entry)

    elapsed = round(time.monotonic() - t0, 2)
    logger.info("unified_search done elapsed=%.2fs total=%d", elapsed, total)

    return {
        "target": target,
        "target_type": target_type,
        "elapsed_seconds": elapsed,
        "total_results": total,
        "sources": by_source,
    }
