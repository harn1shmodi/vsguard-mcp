"""Tests for ASVS loader."""

import pytest
from pathlib import Path

from src.asvs.loader import ASVSLoader
from src.models import ASVSRequirement


class TestASVSLoader:
    """Test ASVS requirement loading."""

    def test_load_asvs_requirements(self):
        """Test loading ASVS requirements from YAML files."""
        loader = ASVSLoader()
        collection = loader.load()

        # Should have loaded requirements
        assert collection.count() > 0
        print(f"Loaded {collection.count()} requirements")

        # Should have multiple categories
        categories = collection.get_categories()
        assert len(categories) > 0
        print(f"Categories: {categories}")

    def test_get_by_id(self):
        """Test getting requirement by ID."""
        loader = ASVSLoader()
        collection = loader.load()

        # Get specific requirement (using V format from ASVS 5.0)
        req = collection.get_by_id("V6.2.1")
        assert req is not None
        assert req.id == "V6.2.1"
        assert "password" in req.requirement.lower()
        assert req.level == 1

    def test_get_by_category(self):
        """Test getting requirements by category."""
        loader = ASVSLoader()
        collection = loader.load()

        # Get password security requirements
        reqs = collection.get_by_category("Password Security")
        assert len(reqs) > 0

        for req in reqs:
            assert req.category == "Password Security"

    def test_get_by_level(self):
        """Test getting requirements by level."""
        loader = ASVSLoader()
        collection = loader.load()

        # Get Level 1 requirements
        level1 = collection.get_by_level(1)
        assert len(level1) > 0

        for req in level1:
            assert req.level == 1

    def test_search_requirements(self):
        """Test searching requirements by text."""
        loader = ASVSLoader()
        collection = loader.load()

        # Search for SQL injection
        results = collection.search("sql injection")
        assert len(results) > 0

        for req in results:
            text = f"{req.requirement} {req.category} {req.chapter}".lower()
            assert "sql" in text or "injection" in text

    def test_requirement_has_required_fields(self):
        """Test that requirements have all required fields from ASVS 5.0."""
        loader = ASVSLoader()
        collection = loader.load()

        req = collection.get_by_id("V6.2.1")
        assert req is not None
        assert req.id == "V6.2.1"
        assert req.requirement is not None and len(req.requirement) > 0
        assert req.category is not None and len(req.category) > 0
        assert req.chapter is not None and len(req.chapter) > 0
        assert req.level in [1, 2, 3]
        # CWE is optional
        # tags should be present
        assert isinstance(req.tags, list)

    def test_caching(self):
        """Test that requirements are cached."""
        loader = ASVSLoader()

        # First load
        collection1 = loader.load()
        count1 = collection1.count()

        # Second load (should be cached)
        collection2 = loader.load()
        count2 = collection2.count()

        assert count1 == count2
        assert collection1 is collection2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

