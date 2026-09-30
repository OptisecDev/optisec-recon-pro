"""Device Fingerprinting — parse User-Agent strings using ua-parser."""

from ua_parser import user_agent_parser

CHIPSET_FAMILIES = {
    "Samsung": ["Exynos", "Snapdragon"],
    "Apple": ["A-series Bionic", "M-series"],
    "Huawei": ["Kirin"],
    "Xiaomi": ["Snapdragon", "MediaTek Dimensity"],
    "OnePlus": ["Snapdragon"],
    "Google": ["Google Tensor"],
    "Motorola": ["Snapdragon"],
}

RELEASE_YEAR_HINTS = {
    # Android version → typical release year range
    "14": "2023-2024",
    "13": "2022-2023",
    "12": "2021-2022",
    "11": "2020-2021",
    "10": "2019-2020",
    "9": "2018-2019",
    "8": "2017-2018",
    "7": "2016-2017",
}

IOS_YEAR = {
    "17": "2023-2024",
    "16": "2022-2023",
    "15": "2021-2022",
    "14": "2020-2021",
    "13": "2019-2020",
    "12": "2018-2019",
}


def fingerprint_device(ua_string: str) -> dict:
    if not ua_string or not ua_string.strip():
        return {"error": "No User-Agent provided"}

    parsed = user_agent_parser.Parse(ua_string)

    os_info = parsed.get("os", {})
    ua_info = parsed.get("user_agent", {})
    device_info = parsed.get("device", {})

    os_family = os_info.get("family", "Unknown")
    os_major = os_info.get("major", "")
    browser_family = ua_info.get("family", "Unknown")
    browser_major = ua_info.get("major", "")
    device_brand = device_info.get("brand") or _infer_brand(ua_string, os_family)
    device_model = device_info.get("model") or "Unknown"
    device_form = _infer_form_factor(os_family, device_brand, ua_string)

    chipset_info = _guess_chipsets(device_brand, ua_string)
    release_year = _estimate_year(os_family, os_major)

    risk_score = _calc_risk(os_family, os_major, browser_family, browser_major)

    return {
        "user_agent": ua_string,
        "device": {
            "brand": device_brand or "Unknown",
            "model": device_model,
            "form_factor": device_form,
        },
        "os": {
            "family": os_family,
            "version": f"{os_major}.{os_info.get('minor', '0')}",
            "major": os_major,
        },
        "browser": {
            "family": browser_family,
            "version": f"{browser_major}.{ua_info.get('minor', '0')}",
            "engine": _infer_engine(browser_family, ua_string),
        },
        "hardware": {
            "possible_chipsets": chipset_info["possible_chipsets"],
            "chipset_confirmed": chipset_info["confirmed"],
            "release_year_estimate": release_year,
        },
        "intelligence": _build_intel(os_family, os_major, browser_family, device_brand),
        "risk_score": risk_score,
        "risk_label": "HIGH" if risk_score > 60 else "MEDIUM" if risk_score > 30 else "LOW",
    }


def _infer_brand(ua: str, os_family: str) -> str:
    ua_lower = ua.lower()
    brands = {
        "samsung": "Samsung", "huawei": "Huawei", "xiaomi": "Xiaomi",
        "redmi": "Xiaomi", "oppo": "OPPO", "vivo": "Vivo",
        "oneplus": "OnePlus", "motorola": "Motorola", "lg": "LG",
        "nokia": "Nokia", "pixel": "Google", "iphone": "Apple",
        "ipad": "Apple", "mac": "Apple",
    }
    for key, brand in brands.items():
        if key in ua_lower:
            return brand
    if os_family == "iOS":
        return "Apple"
    if os_family == "Windows":
        return "PC/Windows"
    if "linux" in ua_lower:
        return "Linux PC"
    return "Unknown"


def _infer_form_factor(os_family: str, brand: str, ua: str) -> str:
    ua_lower = ua.lower()
    if "ipad" in ua_lower or "tablet" in ua_lower:
        return "Tablet"
    if os_family in ("iOS", "Android"):
        return "Smartphone"
    if os_family == "Mac OS X":
        return "MacBook/Desktop"
    if os_family == "Windows":
        return "Laptop/Desktop"
    if "linux" in ua_lower:
        return "Linux Workstation"
    return "Unknown"


_UA_CHIPSET_STRINGS = (
    ("snapdragon", "Qualcomm Snapdragon"),
    ("exynos", "Samsung Exynos"),
    ("dimensity", "MediaTek Dimensity"),
    ("kirin", "HiSilicon Kirin"),
)


def _guess_chipsets(brand: str, ua: str) -> dict:
    """Never claims a single confirmed chipset from brand alone -- a brand
    like Samsung ships multiple chipset families depending on region/model
    (e.g. the global Galaxy S23 is Snapdragon, not Exynos, despite Samsung
    using Exynos elsewhere), so a brand match returns every family the brand
    is known to use, explicitly marked as unconfirmed. Only an explicit
    chipset name appearing in the UA string itself counts as confirmed."""
    ua_lower = ua.lower()
    for needle, name in _UA_CHIPSET_STRINGS:
        if needle in ua_lower:
            return {"possible_chipsets": [name], "confirmed": True}

    chipsets = CHIPSET_FAMILIES.get(brand or "")
    if chipsets:
        return {"possible_chipsets": list(chipsets), "confirmed": False}
    if brand == "Apple":
        return {"possible_chipsets": ["Apple Silicon (A/M-series)"], "confirmed": False}
    return {"possible_chipsets": [], "confirmed": False}


def _estimate_year(os_family: str, major: str) -> str:
    if os_family == "Android" and major:
        return RELEASE_YEAR_HINTS.get(major, "Unknown")
    if os_family == "iOS" and major:
        return IOS_YEAR.get(major, "Unknown")
    if os_family in ("Windows", "Mac OS X", "Linux"):
        return "N/A (desktop)"
    return "Unknown"


def _infer_engine(browser: str, ua: str) -> str:
    browser_lower = browser.lower()
    ua_lower = ua.lower()
    if "gecko" in ua_lower and "webkit" not in ua_lower:
        return "Gecko"
    if browser_lower in ("chrome", "chromium", "edge", "opera", "samsung internet"):
        return "Blink"
    if browser_lower == "safari":
        return "WebKit"
    if browser_lower == "firefox":
        return "Gecko"
    return "Unknown"


def _calc_risk(os_family: str, os_major: str, browser: str, browser_major: str) -> int:
    score = 10
    try:
        if os_family == "Android" and int(os_major or "0") < 10:
            score += 40
        if os_family == "iOS" and int(os_major or "0") < 14:
            score += 30
        if os_family == "Windows" and "XP" in os_major:
            score += 60
    except (ValueError, TypeError):
        pass
    return min(score, 100)


def _build_intel(os_family: str, os_major: str, browser: str, brand: str) -> list:
    notes = []
    try:
        if os_family == "Android" and int(os_major or "99") < 10:
            notes.append("Outdated Android version — high vulnerability risk")
        if os_family == "iOS" and int(os_major or "99") < 14:
            notes.append("Outdated iOS version — patches missing")
    except (ValueError, TypeError):
        pass
    if browser == "Samsung Internet":
        notes.append("Samsung Browser detected — common on older Galaxy devices")
    if os_family == "iOS" and brand == "Apple":
        notes.append("iOS device cannot run APKs; only App Store apps")
    if not notes:
        notes.append("Device appears reasonably modern")
    return notes
