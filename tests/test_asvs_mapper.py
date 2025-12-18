"""Tests for ASVS mapper."""

import pytest

from src.asvs.mapper import ASVSMapper, get_asvs_mapper


class TestASVSMapper:
    """Test ASVS vulnerability mapping."""

    def test_map_sql_injection(self):
        """Test mapping SQL injection to ASVS."""
        mapper = ASVSMapper()
        asvs_ids = mapper.map_vulnerability_to_asvs("sql_injection")

        assert len(asvs_ids) > 0
        assert "V1.2.4" in asvs_ids

    def test_map_xss(self):
        """Test mapping XSS to ASVS."""
        mapper = ASVSMapper()
        asvs_ids = mapper.map_vulnerability_to_asvs("xss")

        assert len(asvs_ids) > 0
        assert "V1.2.1" in asvs_ids or "V1.2.3" in asvs_ids

    def test_map_weak_password(self):
        """Test mapping weak password to ASVS."""
        mapper = ASVSMapper()
        asvs_ids = mapper.map_vulnerability_to_asvs("weak_password")

        assert len(asvs_ids) > 0
        assert "V6.2.1" in asvs_ids or "V6.2.4" in asvs_ids

    def test_map_cwe_to_asvs(self):
        """Test mapping CWE to ASVS."""
        mapper = ASVSMapper()

        # SQL Injection CWE
        asvs_ids = mapper.map_cwe_to_asvs("CWE-89")
        assert len(asvs_ids) > 0
        assert "V1.2.4" in asvs_ids

        # Also test without CWE- prefix
        asvs_ids = mapper.map_cwe_to_asvs("89")
        assert len(asvs_ids) > 0
        assert "V1.2.4" in asvs_ids

    # test_map_code_type_to_categories removed in v2.0.0 - use collection search methods instead

    def test_map_finding_combined(self):
        """Test mapping with both vulnerability type and CWE."""
        mapper = ASVSMapper()

        asvs_ids = mapper.map_finding_to_asvs(
            vulnerability_type="sql_injection", cwe="CWE-89"
        )

        assert len(asvs_ids) > 0
        assert "V1.2.4" in asvs_ids

    def test_singleton_mapper(self):
        """Test that get_asvs_mapper returns singleton."""
        mapper1 = get_asvs_mapper()
        mapper2 = get_asvs_mapper()
        assert mapper1 is mapper2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

