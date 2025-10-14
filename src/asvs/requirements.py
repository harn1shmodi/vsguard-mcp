"""ASVS requirement models and utilities."""

from typing import Optional

from ..models import ASVSRequirement


class ASVSRequirementCollection:
    """Collection of ASVS requirements with fast lookup capabilities."""

    def __init__(self) -> None:
        """Initialize empty collection."""
        self._requirements: dict[str, ASVSRequirement] = {}
        self._by_category: dict[str, list[ASVSRequirement]] = {}
        self._by_level: dict[int, list[ASVSRequirement]] = {}
        self._by_cwe: dict[str, list[ASVSRequirement]] = {}

    def add(self, requirement: ASVSRequirement) -> None:
        """Add a requirement to the collection."""
        # Index by ID
        self._requirements[requirement.id] = requirement

        # Index by category
        if requirement.category not in self._by_category:
            self._by_category[requirement.category] = []
        self._by_category[requirement.category].append(requirement)

        # Index by level
        if requirement.level not in self._by_level:
            self._by_level[requirement.level] = []
        self._by_level[requirement.level].append(requirement)

        # Index by CWE
        if requirement.cwe:
            if requirement.cwe not in self._by_cwe:
                self._by_cwe[requirement.cwe] = []
            self._by_cwe[requirement.cwe].append(requirement)

    def get_by_id(self, requirement_id: str) -> Optional[ASVSRequirement]:
        """Get requirement by ID."""
        return self._requirements.get(requirement_id)

    def get_by_category(self, category: str) -> list[ASVSRequirement]:
        """Get all requirements for a category."""
        return self._by_category.get(category, [])

    def get_by_level(self, level: int) -> list[ASVSRequirement]:
        """Get all requirements for a level."""
        return self._by_level.get(level, [])

    def get_by_cwe(self, cwe: str) -> list[ASVSRequirement]:
        """Get all requirements mapped to a CWE."""
        return self._by_cwe.get(cwe, [])

    def get_all(self) -> list[ASVSRequirement]:
        """Get all requirements."""
        return list(self._requirements.values())

    def count(self) -> int:
        """Get total number of requirements."""
        return len(self._requirements)

    def get_categories(self) -> list[str]:
        """Get all unique categories."""
        return list(self._by_category.keys())

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        level: Optional[int] = None,
        cwe: Optional[str] = None,
    ) -> list[ASVSRequirement]:
        """
        Search requirements by text query with optional filters.

        Args:
            query: Text to search for in requirement, description, or implementation guide
            category: Filter by category
            level: Filter by ASVS level
            cwe: Filter by CWE

        Returns:
            List of matching requirements
        """
        results = self.get_all()

        # Apply filters
        if category:
            results = [r for r in results if r.category == category]
        if level:
            results = [r for r in results if r.level == level]
        if cwe:
            results = [r for r in results if r.cwe == cwe]

        # Text search
        if query:
            query_lower = query.lower()
            results = [
                r
                for r in results
                if query_lower in r.requirement.lower()
                or query_lower in r.description.lower()
                or query_lower in r.implementation_guide.lower()
            ]

        return results

