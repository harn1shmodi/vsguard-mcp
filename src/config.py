"""Configuration management for ASVS MCP Server."""

import os
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Paths
    asvs_data_dir: str = "data/asvs"
    rules_dir: str = "data/rules"
    fixes_dir: str = "data/fixes"

    # Scanner settings
    enable_semgrep: bool = True
    enable_bandit: bool = True
    enable_secrets: bool = True

    # ASVS settings
    min_asvs_level: int = 1  # Only check Level 1 by default

    # Performance
    max_code_size: int = 50000  # Max characters to scan
    scan_timeout: int = 30  # Seconds

    # Logging
    log_level: str = "INFO"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    def get_absolute_path(self, relative_path: str) -> Path:
        """Convert relative path to absolute path from project root."""
        project_root = Path(__file__).parent.parent
        return project_root / relative_path

    @property
    def asvs_data_path(self) -> Path:
        """Get absolute path to ASVS data directory."""
        return self.get_absolute_path(self.asvs_data_dir)

    @property
    def rules_path(self) -> Path:
        """Get absolute path to rules directory."""
        return self.get_absolute_path(self.rules_dir)

    @property
    def fixes_path(self) -> Path:
        """Get absolute path to fixes directory."""
        return self.get_absolute_path(self.fixes_dir)


# Global settings instance
settings = Settings()

