"""Load ASVS requirements from YAML files."""

import logging
from pathlib import Path
from typing import Optional

import yaml

from ..config import settings
from ..models import ASVSRequirement
from .requirements import ASVSRequirementCollection

logger = logging.getLogger(__name__)


class ASVSLoader:
    """Load and cache ASVS requirements from YAML files."""

    def __init__(self, data_dir: Optional[Path] = None) -> None:
        """
        Initialize ASVS loader.

        Args:
            data_dir: Directory containing ASVS YAML files (defaults to config setting)
        """
        self.data_dir = data_dir or settings.asvs_data_path
        self._collection: Optional[ASVSRequirementCollection] = None

    def load(self) -> ASVSRequirementCollection:
        """
        Load all ASVS requirements from YAML files.

        Returns:
            Collection of ASVS requirements

        Raises:
            FileNotFoundError: If data directory doesn't exist
            ValueError: If YAML files are invalid
        """
        if self._collection is not None:
            logger.debug("Returning cached ASVS requirements")
            return self._collection

        if not self.data_dir.exists():
            raise FileNotFoundError(f"ASVS data directory not found: {self.data_dir}")

        logger.info(f"Loading ASVS requirements from {self.data_dir}")
        collection = ASVSRequirementCollection()

        # Load all YAML files in the directory
        yaml_files = sorted(self.data_dir.glob("*.yaml"))
        if not yaml_files:
            yaml_files = sorted(self.data_dir.glob("*.yml"))

        if not yaml_files:
            raise FileNotFoundError(f"No YAML files found in {self.data_dir}")

        for yaml_file in yaml_files:
            logger.debug(f"Loading {yaml_file.name}")
            requirements = self._load_file(yaml_file)
            for req in requirements:
                collection.add(req)

        logger.info(f"Loaded {collection.count()} ASVS requirements from {len(yaml_files)} files")
        self._collection = collection
        return collection

    def _load_file(self, file_path: Path) -> list[ASVSRequirement]:
        """
        Load ASVS requirements from a single YAML file.

        Args:
            file_path: Path to YAML file

        Returns:
            List of ASVS requirements

        Raises:
            ValueError: If YAML is invalid or doesn't match expected schema
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or "requirements" not in data:
                raise ValueError(f"Invalid ASVS file format: {file_path}")

            requirements = []
            for req_data in data["requirements"]:
                try:
                    # Validate and parse with Pydantic
                    requirement = ASVSRequirement(**req_data)
                    requirements.append(requirement)
                except Exception as e:
                    logger.error(f"Error parsing requirement in {file_path}: {e}")
                    logger.debug(f"Invalid requirement data: {req_data}")
                    # Continue loading other requirements
                    continue

            return requirements

        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in {file_path}: {e}")
        except Exception as e:
            raise ValueError(f"Error loading {file_path}: {e}")

    def reload(self) -> ASVSRequirementCollection:
        """Force reload of ASVS requirements from disk."""
        logger.info("Reloading ASVS requirements")
        self._collection = None
        return self.load()

    def get_collection(self) -> ASVSRequirementCollection:
        """Get cached collection or load if not yet loaded."""
        if self._collection is None:
            return self.load()
        return self._collection


# Global loader instance
_loader: Optional[ASVSLoader] = None


def get_asvs_loader() -> ASVSLoader:
    """Get global ASVS loader instance."""
    global _loader
    if _loader is None:
        _loader = ASVSLoader()
    return _loader


def get_asvs_collection() -> ASVSRequirementCollection:
    """Get ASVS requirements collection (convenience function)."""
    loader = get_asvs_loader()
    return loader.get_collection()

