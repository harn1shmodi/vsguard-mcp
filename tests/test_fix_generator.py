"""Tests for fix generator."""

import pytest

from src.fixes.generator import FixGenerator
from src.fixes.templates import get_fix_template, get_supported_vulnerability_types


class TestFixGenerator:
    """Test fix generation."""

    @pytest.mark.asyncio
    async def test_generate_fix_sql_injection(self):
        """Test generating fix for SQL injection."""
        generator = FixGenerator()

        fix = await generator.generate_fix(
            vulnerable_code="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            vulnerability_type="sql_injection",
            language="python",
        )

        assert fix is not None
        assert len(fix.secure_code) > 0
        assert "parameterized" in fix.explanation.lower() or "?" in fix.secure_code
        assert "5.3.4" in fix.asvs_requirements

    @pytest.mark.asyncio
    async def test_generate_fix_xss(self):
        """Test generating fix for XSS."""
        generator = FixGenerator()

        fix = await generator.generate_fix(
            vulnerable_code="<div dangerouslySetInnerHTML={{__html: userInput}} />",
            vulnerability_type="xss",
            language="javascript",
        )

        assert fix is not None
        assert "DOMPurify" in fix.secure_code or "sanitize" in fix.secure_code.lower()
        assert "5.3.3" in fix.asvs_requirements

    @pytest.mark.asyncio
    async def test_generate_fix_weak_password(self):
        """Test generating fix for weak password."""
        generator = FixGenerator()

        fix = await generator.generate_fix(
            vulnerable_code="if len(password) < 6: raise ValueError('Too short')",
            vulnerability_type="weak_password",
            language="python",
        )

        assert fix is not None
        assert "12" in fix.secure_code
        assert "2.1.1" in fix.asvs_requirements

    @pytest.mark.asyncio
    async def test_generate_fix_unknown_vulnerability(self):
        """Test generating fix for unknown vulnerability type."""
        generator = FixGenerator()

        fix = await generator.generate_fix(
            vulnerable_code="some code",
            vulnerability_type="unknown_vuln",
            language="python",
        )

        # Should still return something
        assert fix is not None
        assert len(fix.secure_code) > 0

    def test_get_fix_template(self):
        """Test getting fix template."""
        template = get_fix_template("sql_injection", "python")
        assert template is not None
        assert "vulnerable" in template
        assert "secure" in template
        assert "explanation" in template

    def test_get_supported_vulnerability_types(self):
        """Test getting supported vulnerability types."""
        types = get_supported_vulnerability_types()
        assert len(types) > 0
        assert "sql_injection" in types
        assert "xss" in types
        assert "weak_password" in types


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

