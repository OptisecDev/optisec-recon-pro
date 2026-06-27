import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional
from config import TARGETS_FILE


def _load() -> list:
    if not TARGETS_FILE.exists():
        return []
    try:
        return json.loads(TARGETS_FILE.read_text())
    except Exception:
        return []


def _save(targets: list):
    TARGETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    TARGETS_FILE.write_text(json.dumps(targets, indent=2, ensure_ascii=False))


def add_target(url: str, name: str = "", notes: str = "") -> dict:
    targets = _load()
    target = {
        "id": str(uuid.uuid4())[:8],
        "url": url.strip(),
        "name": name or url,
        "notes": notes,
        "added": datetime.now().isoformat(),
        "scans": []
    }
    targets.append(target)
    _save(targets)
    return target


def list_targets() -> list:
    return _load()


def get_target(target_id: str) -> Optional[dict]:
    for t in _load():
        if t["id"] == target_id:
            return t
    return None


def remove_target(target_id: str) -> bool:
    targets = _load()
    new = [t for t in targets if t["id"] != target_id]
    if len(new) == len(targets):
        return False
    _save(new)
    return True


def record_scan(target_id: str, scan_type: str, results: dict):
    targets = _load()
    for t in targets:
        if t["id"] == target_id:
            t.setdefault("scans", []).append({
                "type": scan_type,
                "timestamp": datetime.now().isoformat(),
                "results": results
            })
            break
    _save(targets)
