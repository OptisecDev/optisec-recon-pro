"""
Tests for the fix to BehavioralAnalyzer._detect_anomalies's off-hours check
(modules/ai_advanced/behavioral.py).

The off-hours anomaly used to always derive the hour from event["timestamp"]
(itself defaulted to the server's real current time in record_event() when
the caller didn't send a timestamp), silently ignoring any "hour" field a
caller sent in the event payload -- e.g. POST /ai-security/api/behavioral/event
with event={"hour": 3, ...} to flag/backfill an event that happened at 3am
without constructing a full ISO "timestamp" for it. The fix now prefers an
explicit event["hour"] when present, and only falls back to
event["timestamp"] (and from there to the server clock, unchanged) when
"hour" is absent or unusable.

Calls BehavioralAnalyzer._detect_anomalies() directly rather than going
through record_event()/the API route, since that method is pure (no disk
I/O -- record_event() persists to data/behavioral_profiles.json via
_load_profiles()/_save_profiles(), which is out of scope for this fix).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.ai_advanced.behavioral import BehavioralAnalyzer

analyzer = BehavioralAnalyzer()


def _empty_profile():
    return {"events": [], "risk_score": 0.0}


def _off_hours_types(anomalies):
    return [a["type"] for a in anomalies if a["type"] == "off_hours_access"]


def test_explicit_hour_field_flags_off_hours_even_with_normal_hours_timestamp():
    # timestamp says noon (normal hours), but the caller explicitly says
    # this event happened at 03:00 -- the explicit hour must win.
    event = {"timestamp": "2024-01-15T12:00:00", "hour": 3}
    anomalies = analyzer._detect_anomalies(_empty_profile(), event)
    assert _off_hours_types(anomalies) == ["off_hours_access"]


def test_explicit_hour_field_suppresses_off_hours_even_with_off_hours_timestamp():
    # timestamp says 03:00 (off-hours), but the caller explicitly says this
    # event happened at 14:00 -- the explicit hour must win, not the
    # timestamp-derived one.
    event = {"timestamp": "2024-01-15T03:00:00", "hour": 14}
    anomalies = analyzer._detect_anomalies(_empty_profile(), event)
    assert _off_hours_types(anomalies) == []


def test_hour_field_absent_falls_back_to_timestamp_derived_hour_off_hours():
    event = {"timestamp": "2024-01-15T03:00:00"}
    anomalies = analyzer._detect_anomalies(_empty_profile(), event)
    assert _off_hours_types(anomalies) == ["off_hours_access"]


def test_hour_field_absent_falls_back_to_timestamp_derived_hour_normal_hours():
    event = {"timestamp": "2024-01-15T14:00:00"}
    anomalies = analyzer._detect_anomalies(_empty_profile(), event)
    assert _off_hours_types(anomalies) == []


def test_unusable_hour_field_falls_back_to_timestamp_instead_of_crashing():
    # A malformed "hour" (not int-coercible) must not blow up the whole
    # anomaly scan -- fall back to the timestamp-derived hour instead.
    event = {"timestamp": "2024-01-15T03:00:00", "hour": "not-a-number"}
    anomalies = analyzer._detect_anomalies(_empty_profile(), event)
    assert _off_hours_types(anomalies) == ["off_hours_access"]


def test_hour_field_boundaries_are_inclusive_of_normal_hours():
    for hour in (6, 22):
        event = {"timestamp": "2024-01-15T12:00:00", "hour": hour}
        anomalies = analyzer._detect_anomalies(_empty_profile(), event)
        assert _off_hours_types(anomalies) == [], f"hour={hour} should be normal hours"


def test_hour_field_boundaries_flag_just_outside_normal_hours():
    for hour in (5, 23):
        event = {"timestamp": "2024-01-15T12:00:00", "hour": hour}
        anomalies = analyzer._detect_anomalies(_empty_profile(), event)
        assert _off_hours_types(anomalies) == ["off_hours_access"], f"hour={hour} should be off-hours"


def test_hour_field_as_numeric_string_is_coerced():
    # JSON callers may send "hour" as a string; it must still be honored.
    event = {"timestamp": "2024-01-15T12:00:00", "hour": "3"}
    anomalies = analyzer._detect_anomalies(_empty_profile(), event)
    assert _off_hours_types(anomalies) == ["off_hours_access"]
