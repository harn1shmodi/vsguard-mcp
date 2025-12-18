"""Tests for ASVS requirements search functionality."""

import pytest
from src.asvs.loader import get_asvs_collection


class TestRequirementsSearch:
    """Test search functionality of ASVS collection."""
    
    def test_search_by_category(self):
        """Test searching by category."""
        collection = get_asvs_collection()
        results = collection.get_by_category("Password Security")
        
        assert len(results) > 0
        assert all(r.category == "Password Security" for r in results)
        assert any(r.id == "V6.2.1" for r in results)
    
    def test_search_by_chapter(self):
        """Test searching by chapter."""
        collection = get_asvs_collection()
        results = collection.get_by_chapter("Authentication")
        
        assert len(results) > 0
        assert all(r.chapter == "Authentication" for r in results)
        # Should include requirements from multiple categories
        categories = set(r.category for r in results)
        assert len(categories) > 1
    
    def test_search_with_level_filter(self):
        """Test filtering by level."""
        collection = get_asvs_collection()
        results = collection.search(
            category="Password Security",
            level=1
        )
        
        assert len(results) > 0
        assert all(r.level >= 1 for r in results)
        assert all(r.category == "Password Security" for r in results)
    
    def test_search_by_query(self):
        """Test free-text search."""
        collection = get_asvs_collection()
        results = collection.search(query="brute force")
        
        assert len(results) > 0
        # Should find requirements mentioning brute force
        assert any("brute" in r.requirement.lower() for r in results)
    
    def test_combined_search(self):
        """Test combining multiple filters."""
        collection = get_asvs_collection()
        results = collection.search(
            chapter="Authentication",
            level=1,
            query="password"
        )
        
        assert len(results) > 0
        assert all(r.chapter == "Authentication" for r in results)
        assert all(r.level >= 1 for r in results)
    
    def test_search_invalid_category(self):
        """Test search with non-existent category."""
        collection = get_asvs_collection()
        results = collection.get_by_category("Nonexistent Category")
        
        assert len(results) == 0
    
    def test_search_invalid_chapter(self):
        """Test search with non-existent chapter."""
        collection = get_asvs_collection()
        results = collection.get_by_chapter("Nonexistent Chapter")
        
        assert len(results) == 0
    
    def test_level_filtering_reduces_results(self):
        """Test that level filtering returns ONLY the specified level (exact match)."""
        collection = get_asvs_collection()
        
        all_results = collection.get_by_category("Password Security")
        level1_results = collection.search(category="Password Security", level=1)
        level2_results = collection.search(category="Password Security", level=2)
        
        # Level 1 should return ONLY L1 requirements (exact match)
        assert all(r.level == 1 for r in level1_results), "All L1 results should be level 1"
        assert all(r.level == 2 for r in level2_results), "All L2 results should be level 2"
        
        # Filtered results should be less than all results
        assert len(level1_results) < len(all_results)
        
        # L1 count + L2 count should equal total (since Password Security has only L1 and L2)
        assert len(level1_results) + len(level2_results) == len(all_results)
    
    def test_multiple_level_filtering(self):
        """Test that multiple level filtering works correctly."""
        collection = get_asvs_collection()
        
        # Get all authentication documentation requirements
        all_results = collection.get_by_category("Authentication Documentation")
        
        # This category has L1 and L2 requirements
        l1_only = collection.search(category="Authentication Documentation", level=1)
        l2_only = collection.search(category="Authentication Documentation", level=2)
        
        # Count should match
        assert len(l1_only) == 1, "Should have 1 L1 requirement"
        assert len(l2_only) == 2, "Should have 2 L2 requirements"
        assert len(all_results) == 3, "Should have 3 total requirements"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

