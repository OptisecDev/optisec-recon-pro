"""Full MITRE ATT&CK Enterprise Navigator — real tactics/techniques/groups
loaded from data/mitre_attack_enterprise_slim.json and
data/mitre_attack_groups_slim.json (distilled from MITRE's official
enterprise-attack.json STIX bundle by scripts/build_mitre_data.py — see
that script's docstring for why a distilled copy is embedded instead of
the full 46MB bundle). Neither file carries a "severity"/"risk_level"
field: MITRE ATT&CK doesn't score either, so this module no longer invents
one (a prior revision assigned arbitrary per-technique severity and
per-group risk_level; both were removed, not relabeled, since there's no
honest value to show)."""
import json
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

DATA_FILE = Path("data/attack_navigator_state.json")
MITRE_TECHNIQUES_FILE = Path("data/mitre_attack_enterprise_slim.json")
MITRE_GROUPS_FILE = Path("data/mitre_attack_groups_slim.json")

# UI-only styling (not a MITRE field) — one color per tactic shortname, used
# solely to color-code matrix columns. Falls back to a neutral gray for any
# tactic a future ATT&CK release adds that isn't in this palette yet.
_TACTIC_COLOR_BY_SHORTNAME = {
    "reconnaissance":       "#8D6E63",
    "resource-development": "#78909C",
    "initial-access":       "#FF6B6B",
    "execution":            "#FF8E53",
    "persistence":          "#FFA726",
    "privilege-escalation": "#FFCA28",
    "defense-evasion":      "#D4E157",
    "stealth":              "#D4E157",
    "defense-impairment":   "#9CCC65",
    "credential-access":    "#66BB6A",
    "discovery":            "#26C6DA",
    "lateral-movement":     "#42A5F5",
    "collection":           "#7E57C2",
    "command-and-control":  "#EC407A",
    "exfiltration":         "#AB47BC",
    "impact":               "#EF5350",
}
_DEFAULT_TACTIC_COLOR = "#90A4AE"


def _load_mitre_json(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text())
    except Exception:
        logger.error("Failed to load MITRE ATT&CK data file %s — Attack Navigator "
                      "will report an empty matrix rather than fabricate one.", path,
                      exc_info=True)
        return None


def _build_tactics_and_techniques() -> tuple[List[dict], Dict[str, List[dict]], dict]:
    doc = _load_mitre_json(MITRE_TECHNIQUES_FILE)
    if doc is None:
        return [], {}, {}

    tactics = []
    shortname_to_id = {}
    for t in doc.get("tactics", []):
        tactics.append({
            "id": t["id"],
            "name": t["name"],
            "shortname": t["shortname"],
            "color": _TACTIC_COLOR_BY_SHORTNAME.get(t["shortname"], _DEFAULT_TACTIC_COLOR),
        })
        shortname_to_id[t["shortname"]] = t["id"]

    techniques: Dict[str, List[dict]] = {t["id"]: [] for t in tactics}
    for tech in doc.get("techniques", []):
        entry = {
            "id": tech["id"],
            "name": tech["name"],
            "sub": tech["id"].split(".")[0] if tech.get("is_subtechnique") else None,
            "platforms": tech.get("platforms", []),
            "description": tech.get("description", ""),
        }
        for shortname in tech.get("tactics", []):
            tac_id = shortname_to_id.get(shortname)
            if tac_id:
                techniques[tac_id].append(entry)

    return tactics, techniques, doc.get("_meta", {})


def _build_apt_groups() -> tuple[List[dict], dict]:
    doc = _load_mitre_json(MITRE_GROUPS_FILE)
    if doc is None:
        return [], {}
    groups = [
        {
            "id": g["id"],
            "name": g["name"],
            "aliases": g.get("aliases", []),
            "description": g.get("description", ""),
            "url": g.get("url"),
            "techniques": g.get("techniques", []),
            "malware": g.get("malware", []),
        }
        for g in doc.get("groups", [])
    ]
    return groups, doc.get("_meta", {})


TACTICS, TECHNIQUES, _TECHNIQUES_META = _build_tactics_and_techniques()
APT_GROUPS, _GROUPS_META = _build_apt_groups()

# ── IOC Indicator Types ────────────────────────────────────────────────────────

IOC_TYPES = [
    "ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "hash_sha512",
    "email", "user_agent", "mutex", "registry_key", "file_path", "file_name",
    "cve", "asn", "cidr", "bitcoin_address", "mac_address", "ja3_hash",
    "yara_rule", "ssdeep", "imphash", "tlsh", "certificate_sha1",
    "process_name", "service_name", "scheduled_task", "network_share",
    "dns_query", "http_method", "http_header", "cookie_value",
    "uri_parameter", "email_subject", "email_attachment", "email_sender",
    "phone_number", "social_media_handle", "username", "password_hash",
    "api_key", "jwt_token", "tls_fingerprint", "port", "protocol",
    "malware_family", "campaign_name", "threat_actor",
]


def _load_state() -> dict:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    if DATA_FILE.exists():
        try:
            return json.loads(DATA_FILE.read_text())
        except Exception:
            pass
    return {"detections": [], "custom_layers": [], "ioc_hits": []}


def _save_state(state: dict) -> None:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    DATA_FILE.write_text(json.dumps(state, indent=2, default=str))


def get_full_matrix() -> dict:
    """Return the complete ATT&CK matrix structure, plus where it came from.

    `data_source` is honest about provenance either way: when
    MITRE_TECHNIQUES_FILE loaded fine it names the real source/fetch date;
    when it didn't (missing/corrupt file), tactics/techniques are empty
    rather than silently falling back to fabricated data, and
    `data_source.error` says so.
    """
    matrix = []
    total_techniques = 0
    for tactic in TACTICS:
        tac_id = tactic["id"]
        techs = TECHNIQUES.get(tac_id, [])
        total_techniques += len(techs)
        matrix.append({
            **tactic,
            "techniques": techs,
            "technique_count": len(techs),
        })
    data_source = dict(_TECHNIQUES_META) if _TECHNIQUES_META else {
        "error": f"{MITRE_TECHNIQUES_FILE} missing or unreadable — matrix is empty, not fabricated"
    }
    return {
        "tactics": matrix,
        "total_techniques": total_techniques,
        "total_tactics": len(TACTICS),
        "data_source": data_source,
    }


def get_apt_profiles() -> List[dict]:
    return APT_GROUPS


def get_ioc_types() -> List[str]:
    return IOC_TYPES


def detect_techniques_in_iocs(ioc_list: List[dict]) -> dict:
    """Map a list of IOCs to likely MITRE techniques."""
    hits: Dict[str, dict] = {}
    for ioc in ioc_list:
        ioc_type = ioc.get("type", "")
        value = ioc.get("value", "")

        mappings = _ioc_to_technique_map(ioc_type, value)
        for tech_id, tactic_id in mappings:
            if tech_id not in hits:
                tech_info = _find_technique(tech_id)
                hits[tech_id] = {
                    "technique_id": tech_id,
                    "technique_name": tech_info.get("name", tech_id),
                    "tactic_id": tactic_id,
                    "ioc_count": 0,
                    "iocs": [],
                }
            hits[tech_id]["ioc_count"] += 1
            hits[tech_id]["iocs"].append({"type": ioc_type, "value": value[:80]})

    return {
        "technique_hits": list(hits.values()),
        "total_hits": len(hits),
        "iocs_processed": len(ioc_list),
    }


def _ioc_to_technique_map(ioc_type: str, value: str) -> List[tuple]:
    mapping = {
        "ip":              [("T1071", "TA0011"), ("T1090", "TA0011")],
        "domain":          [("T1568.002", "TA0011"), ("T1071.001", "TA0011")],
        "url":             [("T1566.002", "TA0001"), ("T1071.001", "TA0011")],
        "hash_md5":        [("T1027", "TA0005"), ("T1587.001", "TA0042")],
        "hash_sha256":     [("T1027", "TA0005"), ("T1587.001", "TA0042")],
        "email":           [("T1566", "TA0001"), ("T1589.002", "TA0043")],
        "user_agent":      [("T1071.001", "TA0011"), ("T1036", "TA0005")],
        "mutex":           [("T1480", "TA0005"), ("T1027", "TA0005")],
        "registry_key":    [("T1547.001", "TA0003"), ("T1112", "TA0005")],
        "cve":             [("T1190", "TA0001"), ("T1211", "TA0005")],
        "bitcoin_address": [("T1486", "TA0040"), ("T1020", "TA0010")],
        "ja3_hash":        [("T1573", "TA0011"), ("T1071", "TA0011")],
        "malware_family":  [("T1587.001", "TA0042"), ("T1027", "TA0005")],
        "certificate_sha1":[("T1553", "TA0005"), ("T1573.002", "TA0011")],
        "dns_query":       [("T1071.004", "TA0011"), ("T1568", "TA0011")],
        "process_name":    [("T1055", "TA0004"), ("T1059", "TA0002")],
    }
    return mapping.get(ioc_type, [("T1027", "TA0005")])


def _find_technique(tech_id: str) -> dict:
    for techs in TECHNIQUES.values():
        for t in techs:
            if t["id"] == tech_id:
                return t
    return {"name": tech_id}


_MAX_SOURCE_LEN = 100
_MAX_DETAILS_LEN = 2000


def add_detection(technique_id: str, confidence: int, source: str, details: str = "",
                   user_id: Optional[int] = None) -> dict:
    """Record a detection, owned by `user_id`.

    technique_id must name a real MITRE technique -- _find_technique()
    used to fall back to echoing back whatever string was passed for an
    unrecognized id, which (combined with web/templates/attack_navigator.html
    rendering technique_id/technique_name/source unescaped -- now fixed
    separately) let an unvalidated technique_id or source double as a
    stored-XSS payload for every other viewer of the Detections tab.
    """
    tech = _find_technique(technique_id)
    if "id" not in tech:  # _find_technique()'s not-found fallback is {"name": technique_id}
        raise ValueError(f"Unknown technique_id: {technique_id}")

    state = _load_state()
    detection = {
        "id": hashlib.md5(f"{technique_id}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:8],
        "technique_id": technique_id,
        "technique_name": tech["name"],
        "confidence": min(100, max(0, confidence)),
        "source": (source or "manual").strip()[:_MAX_SOURCE_LEN],
        "details": (details or "").strip()[:_MAX_DETAILS_LEN],
        "timestamp": datetime.utcnow().isoformat(),
        "user_id": user_id,
    }
    state["detections"].insert(0, detection)
    state["detections"] = state["detections"][:500]
    _save_state(state)
    return detection


def get_detections(limit: int = 50, user_id: Optional[int] = None, is_admin: bool = False) -> List[dict]:
    """Detections owned by `user_id` (admin sees every account's -- same
    admin-sees-all convention as modules/ai_advanced/{zero_day,red_team}.py,
    modules/darkweb/intelligence.py, modules/quantum/encryption.py).
    Defaults (user_id=None, is_admin=False) return everything, for any
    other internal caller; web/routers/attack_navigator.py always passes
    explicit values."""
    detections = _load_state()["detections"]
    if not (is_admin or user_id is None):
        detections = [d for d in detections if d.get("user_id") == user_id]
    return detections[:limit]


def get_matrix_coverage(detections: List[dict]) -> dict:
    """Compute which tactics/techniques have been detected."""
    detected_ids = {d["technique_id"] for d in detections}
    coverage = {}
    for tac in TACTICS:
        techs = TECHNIQUES.get(tac["id"], [])
        covered = [t for t in techs if t["id"] in detected_ids]
        coverage[tac["id"]] = {
            "tactic_name": tac["name"],
            "total": len(techs),
            "covered": len(covered),
            "pct": round(len(covered) / len(techs) * 100, 1) if techs else 0,
        }
    return coverage
