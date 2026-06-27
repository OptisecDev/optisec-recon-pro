"""Behavioral Analysis — user/entity behavior analytics (UEBA) with ML-style scoring."""

import json
import math
import asyncio
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
from typing import Optional

BEHAVIOR_DB = Path("data/behavioral_profiles.json")


def _load_profiles() -> dict:
    BEHAVIOR_DB.parent.mkdir(parents=True, exist_ok=True)
    if BEHAVIOR_DB.exists():
        return json.loads(BEHAVIOR_DB.read_text())
    return {}


def _save_profiles(profiles: dict) -> None:
    BEHAVIOR_DB.parent.mkdir(parents=True, exist_ok=True)
    BEHAVIOR_DB.write_text(json.dumps(profiles, indent=2, default=str))


class BehavioralAnalyzer:
    """UEBA engine — builds entity profiles and detects anomalies."""

    RISK_WEIGHTS = {
        "impossible_travel": 0.9,
        "credential_stuffing": 0.85,
        "off_hours_access": 0.4,
        "new_device": 0.35,
        "privilege_escalation": 0.95,
        "mass_data_download": 0.8,
        "api_abuse": 0.7,
        "lateral_movement": 0.85,
        "brute_force": 0.75,
        "new_country": 0.5,
        "unusual_endpoint": 0.3,
        "high_request_rate": 0.6,
    }

    def record_event(self, entity_id: str, event: dict) -> dict:
        profiles = _load_profiles()
        profile = profiles.get(entity_id, self._blank_profile(entity_id))

        event["timestamp"] = event.get("timestamp", datetime.utcnow().isoformat())
        profile["events"].append(event)
        profile["events"] = profile["events"][-1000:]  # keep last 1000

        anomalies = self._detect_anomalies(profile, event)
        risk_score = self._calc_risk(anomalies, profile)

        profile["risk_score"] = risk_score
        profile["last_seen"] = event["timestamp"]
        profile["total_events"] = profile.get("total_events", 0) + 1
        if anomalies:
            profile["anomaly_log"].append({
                "timestamp": event["timestamp"],
                "anomalies": anomalies,
                "risk_score": risk_score,
            })
            profile["anomaly_log"] = profile["anomaly_log"][-100:]

        profiles[entity_id] = profile
        _save_profiles(profiles)
        return {
            "entity_id": entity_id,
            "anomalies": anomalies,
            "risk_score": risk_score,
            "risk_level": self._risk_level(risk_score),
            "action": self._recommend_action(risk_score, anomalies),
        }

    def _detect_anomalies(self, profile: dict, event: dict) -> list:
        anomalies = []
        events = profile["events"]

        # Impossible travel
        if event.get("ip") and len(events) >= 2:
            prev = next((e for e in reversed(events[:-1]) if e.get("ip")), None)
            if prev and prev["ip"] != event["ip"]:
                prev_time = datetime.fromisoformat(prev["timestamp"])
                curr_time = datetime.fromisoformat(event["timestamp"])
                delta_mins = abs((curr_time - prev_time).total_seconds() / 60)
                if delta_mins < 10 and prev["ip"] != event["ip"]:
                    anomalies.append({
                        "type": "impossible_travel",
                        "detail": f"IP changed from {prev['ip']} to {event['ip']} in {delta_mins:.1f} min",
                    })

        # Brute force
        recent = [e for e in events[-20:] if e.get("action") == "login_failed"]
        if len(recent) >= 5:
            anomalies.append({
                "type": "brute_force",
                "detail": f"{len(recent)} failed logins in last 20 events",
            })

        # Off-hours access
        hour = datetime.fromisoformat(event["timestamp"]).hour
        if hour < 6 or hour > 22:
            anomalies.append({
                "type": "off_hours_access",
                "detail": f"Activity at {hour:02d}:00 (outside normal hours)",
            })

        # High request rate
        last_minute = [e for e in events if self._within_seconds(e["timestamp"], event["timestamp"], 60)]
        if len(last_minute) > 50:
            anomalies.append({
                "type": "high_request_rate",
                "detail": f"{len(last_minute)} requests in 60 seconds",
            })

        # Privilege escalation
        if event.get("action") in ("sudo", "privilege_change", "role_assign", "admin_access"):
            anomalies.append({
                "type": "privilege_escalation",
                "detail": f"Privileged action: {event.get('action')}",
            })

        # Mass data download
        if event.get("bytes_transferred", 0) > 100_000_000:
            anomalies.append({
                "type": "mass_data_download",
                "detail": f"Downloaded {event['bytes_transferred'] / 1e6:.1f} MB",
            })

        # New device/country
        known_ips = {e.get("ip") for e in events[:-1] if e.get("ip")}
        if event.get("ip") and event["ip"] not in known_ips and len(known_ips) > 3:
            anomalies.append({
                "type": "new_device",
                "detail": f"First seen IP: {event.get('ip')}",
            })

        return anomalies

    def _calc_risk(self, anomalies: list, profile: dict) -> float:
        if not anomalies:
            base = profile.get("risk_score", 0.0)
            return max(0.0, base * 0.9)  # decay

        scores = [self.RISK_WEIGHTS.get(a["type"], 0.3) for a in anomalies]
        combined = 1.0 - math.prod(1.0 - s for s in scores)
        return round(min(combined, 1.0), 3)

    def _risk_level(self, score: float) -> str:
        if score >= 0.8: return "critical"
        if score >= 0.6: return "high"
        if score >= 0.35: return "medium"
        if score > 0.0: return "low"
        return "normal"

    def _recommend_action(self, score: float, anomalies: list) -> str:
        if score >= 0.8: return "block_and_alert"
        if score >= 0.6: return "require_mfa"
        if score >= 0.35: return "alert_soc"
        return "monitor"

    def _within_seconds(self, ts1: str, ts2: str, seconds: int) -> bool:
        try:
            t1 = datetime.fromisoformat(ts1)
            t2 = datetime.fromisoformat(ts2)
            return abs((t2 - t1).total_seconds()) <= seconds
        except Exception:
            return False

    def _blank_profile(self, entity_id: str) -> dict:
        return {
            "entity_id": entity_id,
            "created_at": datetime.utcnow().isoformat(),
            "last_seen": None,
            "risk_score": 0.0,
            "total_events": 0,
            "events": [],
            "anomaly_log": [],
        }

    def get_profile(self, entity_id: str) -> Optional[dict]:
        return _load_profiles().get(entity_id)

    def list_high_risk(self, threshold: float = 0.5) -> list:
        profiles = _load_profiles()
        return sorted(
            [{"entity_id": k, "risk_score": v["risk_score"],
              "last_seen": v["last_seen"], "total_events": v["total_events"]}
             for k, v in profiles.items() if v.get("risk_score", 0) >= threshold],
            key=lambda x: -x["risk_score"],
        )

    def get_all_entities(self) -> list:
        profiles = _load_profiles()
        return [
            {
                "entity_id": k,
                "risk_score": v.get("risk_score", 0),
                "risk_level": self._risk_level(v.get("risk_score", 0)),
                "total_events": v.get("total_events", 0),
                "last_seen": v.get("last_seen"),
                "anomaly_count": len(v.get("anomaly_log", [])),
            }
            for k, v in profiles.items()
        ]


analyzer = BehavioralAnalyzer()
