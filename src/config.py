"""Configuration management for ASVS MCP Server."""

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

# Import data package paths
import data


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Scanner settings
    enable_semgrep: bool = True
    enable_bandit: bool = True
    enable_secrets: bool = True

    # ASVS settings
    min_asvs_level: int = 1

    # Performance
    max_code_size: int = 50000
    scan_timeout: int = 30

    # Logging
    log_level: str = "INFO"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @property
    def asvs_data_path(self) -> Path:
        """Get absolute path to ASVS data directory."""
        return data.ASVS_DIR

    @property
    def rules_path(self) -> Path:
        """Get absolute path to rules directory."""
        return data.RULES_DIR

    @property
    def fixes_path(self) -> Path:
        """Get absolute path to fixes directory."""
        return data.DATA_DIR / "fixes"


# Global settings instance
settings = Settings()

