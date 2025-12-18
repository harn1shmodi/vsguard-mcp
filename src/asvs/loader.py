"""Load ASVS requirements from official OWASP JSON files."""

import json
import logging
from pathlib import Path
from typing import Optional

import data

from ..models import ASVSRequirement
from .requirements import ASVSRequirementCollection
from .utils import asvs_to_cwe_key, generate_tags

logger = logging.getLogger(__name__)


class ASVSLoader:
    """Load and cache ASVS requirements from official OWASP JSON."""

    def __init__(
        self,
        asvs_path: Optional[Path] = None,
        cwe_mapping_path: Optional[Path] = None,
    ) -> None:
        """
        Initialize ASVS loader with official JSON files.

        Args:
            asvs_path: Path to official ASVS JSON (defaults to data/asvs_official.json)
            cwe_mapping_path: Path to CWE mapping JSON (defaults to data/ASVS 5.0 BE CWE Mapping.json)
        """
        self.asvs_path = asvs_path or (data.DATA_DIR / "asvs_official.json")
        self.cwe_mapping_path = cwe_mapping_path or (data.DATA_DIR / "ASVS 5.0 BE CWE Mapping.json")
        self._collection: Optional[ASVSRequirementCollection] = None

    def load(self) -> ASVSRequirementCollection:
        """
        Load all ASVS requirements from official JSON files.

        Returns:
            Collection of ASVS requirements

        Raises:
            FileNotFoundError: If JSON files don't exist
            ValueError: If JSON files are invalid
        """
        if self._collection is not None:
            logger.debug("Returning cached ASVS requirements")
            return self._collection

        if not self.asvs_path.exists():
            raise FileNotFoundError(f"ASVS official JSON not found: {self.asvs_path}")

        if not self.cwe_mapping_path.exists():
            raise FileNotFoundError(f"CWE mapping JSON not found: {self.cwe_mapping_path}")

        logger.info(f"Loading ASVS requirements from {self.asvs_path}")

        # Load official ASVS JSON
        with open(self.asvs_path, "r", encoding="utf-8") as f:
            asvs_data = json.load(f)

        # Load official CWE mappings
        with open(self.cwe_mapping_path, "r", encoding="utf-8") as f:
            cwe_mappings = json.load(f)

        # Parse requirements
        collection = ASVSRequirementCollection()

        for chapter in asvs_data.get("Requirements", []):
            chapter_name = chapter.get("Name", "")

            for section in chapter.get("Items", []):
                section_name = section.get("Name", "")

                for item in section.get("Items", []):
                    try:
                        requirement = self._parse_requirement(
                            item, chapter_name, section_name, cwe_mappings
                        )
                        collection.add(requirement)
                    except Exception as e:
                        logger.error(f"Error parsing requirement {item.get('Shortcode')}: {e}")
                        continue

        logger.info(f"Loaded {collection.count()} ASVS requirements from official JSON")
        self._collection = collection
        return collection

    def _parse_requirement(
        self,
        item: dict,
        chapter_name: str,
        section_name: str,
        cwe_mappings: dict,
    ) -> ASVSRequirement:
        """
        Parse a single requirement from official JSON.

        Args:
            item: Requirement item from JSON
            chapter_name: Parent chapter name
            section_name: Parent section name
            cwe_mappings: CWE mapping dictionary

        Returns:
            Parsed ASVS requirement
        """
        req_id = item["Shortcode"]
        level = int(item["L"])
        description = item["Description"]

        # Map to CWE using official mapping
        cwe_key = asvs_to_cwe_key(req_id)
        cwe_id = cwe_mappings.get(cwe_key)
        cwe_list = [f"CWE-{cwe_id}"] if cwe_id else None

        # Generate searchable tags
        tags = generate_tags(chapter_name, section_name)

        return ASVSRequirement(
            id=req_id,
            level=level,
            category=section_name,
            chapter=chapter_name,
            requirement=description,
            cwe=cwe_list,
            tags=tags,
        )

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
