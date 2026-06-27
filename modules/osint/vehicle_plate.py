"""Iraqi Vehicle Plate Intelligence — format recognition and province decoding."""

import re

# Iraqi province codes used in plates (first 1-2 digits of old system)
IRAQ_PROVINCES = {
    "1":  {"name": "Baghdad",          "arabic": "بغداد",        "region": "Central"},
    "2":  {"name": "Basra",            "arabic": "البصرة",       "region": "South"},
    "3":  {"name": "Nineveh",          "arabic": "نينوى",        "region": "North"},
    "4":  {"name": "Erbil",            "arabic": "أربيل",        "region": "Kurdistan"},
    "5":  {"name": "Sulaymaniyah",     "arabic": "السليمانية",   "region": "Kurdistan"},
    "6":  {"name": "Duhok",            "arabic": "دهوك",         "region": "Kurdistan"},
    "7":  {"name": "Kirkuk",           "arabic": "كركوك",        "region": "North"},
    "8":  {"name": "Diyala",           "arabic": "ديالى",        "region": "Central"},
    "9":  {"name": "Wasit",            "arabic": "واسط",         "region": "Central"},
    "10": {"name": "Babil",            "arabic": "بابل",         "region": "Central"},
    "11": {"name": "Karbala",          "arabic": "كربلاء",       "region": "Central"},
    "12": {"name": "Najaf",            "arabic": "النجف",        "region": "Central"},
    "13": {"name": "Qadisiyyah",       "arabic": "القادسية",     "region": "Central"},
    "14": {"name": "Muthanna",         "arabic": "المثنى",       "region": "South"},
    "15": {"name": "Dhi Qar",          "arabic": "ذي قار",       "region": "South"},
    "16": {"name": "Maysan",           "arabic": "ميسان",        "region": "South"},
    "17": {"name": "Saladin",          "arabic": "صلاح الدين",   "region": "Central"},
    "18": {"name": "Anbar",            "arabic": "الأنبار",      "region": "West"},
}

# New Iraqi plate format: Letter(s) + digits (post-2009)
# Old format: number + digits + letter sequence
NEW_PLATE_RE = re.compile(
    r"^([أ-ي]{1,3}|[A-Za-z]{1,3})\s*(\d{4,6})$"
)
OLD_PLATE_RE = re.compile(
    r"^(\d{1,2})\s*[/\-]?\s*(\d{3,5})\s*([أ-يA-Za-z]{1,3})$"
)
DIPLOMATIC_RE = re.compile(r"^(CD|CC|TC)\s*(\d{3,5})$", re.IGNORECASE)
MILITARY_RE = re.compile(r"^(م|ع|ق|M|A)\s*(\d{4,6})$", re.IGNORECASE)


def decode_plate(plate_raw: str) -> dict:
    plate = plate_raw.strip().upper()

    if DIPLOMATIC_RE.match(plate):
        return _make_result(plate, "Diplomatic", _diplomatic_notes(plate))

    if MILITARY_RE.match(plate):
        return _make_result(plate, "Military/Government", ["Military or government vehicle — restricted tracking"])

    # Try new format
    m = NEW_PLATE_RE.match(plate)
    if m:
        letters, numbers = m.group(1), m.group(2)
        return _make_result(plate, "New Format (Post-2009)", [
            f"Letter prefix: {letters} (regional allocation code)",
            f"Serial: {numbers}",
            "New plates are allocated per province traffic directorate",
        ], province=None, year_est="2009+")

    # Try old format
    m = OLD_PLATE_RE.match(plate)
    if m:
        prov_code, serial, suffix = m.group(1), m.group(2), m.group(3)
        prov = IRAQ_PROVINCES.get(str(int(prov_code)), None)
        prov_name = prov["name"] if prov else f"Unknown (code {prov_code})"
        prov_arabic = prov["arabic"] if prov else ""
        region = prov["region"] if prov else "Unknown"
        notes = [
            f"Province code {prov_code} → {prov_name} ({prov_arabic})",
            f"Region: {region}",
            f"Serial number: {serial}",
            f"Suffix group: {suffix}",
        ]
        return _make_result(plate, "Old Format (Pre-2009)", notes,
                            province=prov_name, province_arabic=prov_arabic,
                            region=region, year_est="Pre-2009")

    # Unknown format — provide basic analysis
    return {
        "plate": plate_raw,
        "valid": False,
        "format": "Unknown",
        "province": None,
        "notes": [
            "Plate does not match known Iraqi formats",
            "Expected: province_code + serial + suffix (old), or letters + 4-6 digits (new)",
        ],
        "risk_score": 50,
        "risk_label": "MEDIUM",
    }


def _make_result(plate: str, fmt: str, notes: list,
                 province: str = None, province_arabic: str = None,
                 region: str = None, year_est: str = None) -> dict:
    return {
        "plate": plate,
        "valid": True,
        "format": fmt,
        "province": province,
        "province_arabic": province_arabic,
        "region": region,
        "year_estimate": year_est,
        "notes": notes,
        "risk_score": 20,
        "risk_label": "LOW",
    }


def _diplomatic_notes(plate: str) -> list:
    prefix = plate[:2].upper()
    types = {"CD": "Corps Diplomatique", "CC": "Consul Corps", "TC": "Technical Cooperation"}
    return [
        f"Type: {types.get(prefix, 'Diplomatic')}",
        "Diplomatic vehicles have immunity in many jurisdictions",
        "Contact Ministry of Foreign Affairs for more details",
    ]


def list_provinces() -> list:
    return [{"code": k, **v} for k, v in IRAQ_PROVINCES.items()]
