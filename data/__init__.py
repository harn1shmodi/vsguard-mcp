"""VSGuard data package containing ASVS requirements and security rules."""

from pathlib import Path

# Expose the data directory path for easy access
DATA_DIR = Path(__file__).parent
ASVS_DIR = DATA_DIR / "asvs"
RULES_DIR = DATA_DIR / "rules"

__all__ = ["DATA_DIR", "ASVS_DIR", "RULES_DIR"]

