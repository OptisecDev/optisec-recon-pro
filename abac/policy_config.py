"""Where the ABAC rules file lives. auth/dependencies.py loads it."""

from pathlib import Path

RULES_PATH_ENV = "ABAC_RULES_PATH"
DEFAULT_RULES_PATH = Path(__file__).resolve().parent / "abac_rules.json"
