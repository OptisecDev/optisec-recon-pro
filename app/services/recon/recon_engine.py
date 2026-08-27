"""Recon engine: live HIBP breach lookups (with mock fallback) + real EXIF
extraction + mock attack-chain simulation. scan_email calls the real
HaveIBeenPwned API via hibp_service and only drops back to mock data if
that call fails outright; extract_exif is real (reads actual image metadata
via Pillow).
"""
import io
import logging
import uuid
from datetime import datetime, timezone
from typing import BinaryIO

import httpx
from PIL import ExifTags, Image

from app.db.session import EternalSessionLocal
from app.models.eternal.simulation_step import SimulationStep
from app.services.external.hibp_service import check_hibp

logger = logging.getLogger("app.services.recon")

# Rough bounding boxes are enough to flag "this coordinate looks real/inhabited"
# rather than (0, 0) or another obviously-placeholder GPS value.
_SENTINEL_COORDS = {(0.0, 0.0)}


def _mock_breaches(email: str) -> dict:
    """Placeholder breach data — used only when the live HIBP call fails."""
    return {
        "email": email,
        "breaches": [
            {
                "source": "LinkedIn",
                "year": 2022,
                "description": f"ظهر هذا البريد ({email}) في تسريب بيانات LinkedIn لعام 2022.",
            },
            {
                "source": "Collection #1",
                "year": 2019,
                "description": f"عُثر على {email} ضمن قاعدة بيانات Collection #1 المسربة.",
            },
        ],
        "mock": True,
        "source": "mock_fallback",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


async def scan_email(email: str) -> dict:
    """Look up real breach data for `email` via HIBP; fall back to mock data
    if the live API is unreachable or errors out."""
    try:
        hibp_result = await check_hibp(email)
    except httpx.HTTPError:
        logger.warning("HIBP lookup failed for %s; falling back to mock data", email)
        return _mock_breaches(email)

    breaches = [
        {
            "source": breach.get("Name"),
            "year": (breach.get("BreachDate") or "")[:4] or None,
            "description": breach.get("Description"),
        }
        for breach in hibp_result["breaches"]
    ]

    return {
        "email": email,
        "breaches": breaches,
        "mock": False,
        "source": "HIBP",
        "message": hibp_result["message"],
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


def _to_degrees(value) -> float:
    d, m, s = value
    return float(d) + float(m) / 60.0 + float(s) / 3600.0


def extract_exif(image_file: BinaryIO | bytes) -> dict:
    """Extract real EXIF metadata (GPS, timestamp, camera) from an uploaded image."""
    data = image_file.read() if hasattr(image_file, "read") else image_file
    image = Image.open(io.BytesIO(data))

    exif_raw = image.getexif()
    if not exif_raw:
        return {"has_exif": False, "warning": None}

    tags = {ExifTags.TAGS.get(tag_id, tag_id): value for tag_id, value in exif_raw.items()}

    gps_info = exif_raw.get_ifd(ExifTags.IFD.GPSInfo) if hasattr(exif_raw, "get_ifd") else {}
    gps_tags = {ExifTags.GPSTAGS.get(k, k): v for k, v in (gps_info or {}).items()}

    result = {
        "has_exif": True,
        "camera_make": tags.get("Make"),
        "camera_model": tags.get("Model"),
        "date_taken": tags.get("DateTimeOriginal") or tags.get("DateTime"),
        "gps": None,
        "warning": None,
    }

    lat_raw = gps_tags.get("GPSLatitude")
    lon_raw = gps_tags.get("GPSLongitude")
    if lat_raw and lon_raw:
        lat = _to_degrees(lat_raw)
        if gps_tags.get("GPSLatitudeRef") == "S":
            lat = -lat
        lon = _to_degrees(lon_raw)
        if gps_tags.get("GPSLongitudeRef") == "W":
            lon = -lon
        result["gps"] = {"latitude": lat, "longitude": lon}
        if (round(lat, 4), round(lon, 4)) not in _SENTINEL_COORDS:
            result["warning"] = (
                "تحذير: تحتوي هذه الصورة على إحداثيات GPS حساسة قد تكشف موقعاً حقيقياً."
            )

    return result


_ATTACK_CHAIN_TEMPLATE = [
    ("Reconnaissance", "جمع معلومات استطلاعية أولية عن الهدف (نطاقات، بريد، خدمات مكشوفة)."),
    ("Initial Access", "محاولة استغلال ثغرة معروفة للوصول الأولي إلى النظام المستهدف."),
    ("Privilege Escalation", "رفع الصلاحيات من مستخدم عادي إلى مستوى إداري."),
    ("Persistence", "زرع آلية للحفاظ على الوصول بعد إعادة التشغيل."),
    ("Impact", "محاكاة هجوم حرمان من الخدمة (DoS) على الخدمة المستهدفة."),
]

# No real engine backs this attack chain — every step is a fixed template
# item, not the outcome of an actual exploitation attempt. Tagged
# simulated=True + a bilingual note on every step, following the same
# `_ar`-suffixed bilingual convention used elsewhere in the project (see
# modules/ai_advanced/autonomous_redteam.py's SIMULATED_NOTE_EN/AR for
# Phases 2/4/5/6, and modules/quantum/encryption.py's mode="simulated").
SIMULATED_NOTE_EN = (
    "Simulated step — this attack chain is a fixed illustrative template, not the "
    "result of a real exploitation attempt against the target. OPTISEC has no live "
    "engine performing initial access, privilege escalation, persistence, or impact "
    "here. This content is illustrative only, not evidence of an actual compromise."
)
SIMULATED_NOTE_AR = (
    "خطوة محاكاة — سلسلة الهجوم هذه قالب توضيحي ثابت، وليست نتيجة محاولة استغلال "
    "فعلية للهدف. لا يمتلك OPTISEC محركاً حقيقياً ينفذ الوصول الأولي، أو رفع "
    "الصلاحيات، أو الثبات، أو التأثير هنا. هذا المحتوى توضيحي فقط، وليس دليلاً على "
    "اختراق فعلي."
)


async def simulate_attack_chain(target_id: uuid.UUID) -> list[dict]:
    """Generate a mock 4-5 step MITRE-tactic attack chain and persist it."""
    now = datetime.now(timezone.utc)
    steps = []
    async with EternalSessionLocal() as db:
        for order, (tactic, description) in enumerate(_ATTACK_CHAIN_TEMPLATE, start=1):
            step = SimulationStep(
                target_id=target_id,
                step_order=order,
                mitre_tactic=tactic,
                description=description,
                executed_at=now,
            )
            db.add(step)
            steps.append(step)
        await db.commit()
        for step in steps:
            await db.refresh(step)

    return [
        {
            "step_order": s.step_order,
            "mitre_tactic": s.mitre_tactic,
            "description": s.description,
            "executed_at": s.executed_at.isoformat(),
            "simulated": True,
            "note": SIMULATED_NOTE_EN,
            "note_ar": SIMULATED_NOTE_AR,
        }
        for s in steps
    ]
