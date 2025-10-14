"""Tests for output formatters."""

import pytest

from src.models import ASVSRequirement, ScanResult, FixSuggestion, Location, SeverityLevel
from src.utils.formatters import (
    format_security_requirements,
    format_scan_results,
    format_fix_suggestion,
)


class TestFormatters:
    """Test output formatting functions."""

    def test_format_security_requirements(self):
        """Test formatting ASVS requirements."""
        req = ASVSRequirement(
            id="2.1.1",
            level=1,
            category="Password Security",
            requirement="Passwords must be at least 12 characters",
            cwe="CWE-521",
            description="Test description",
            implementation_guide="Test guide",
            code_examples=["example code"],
        )

        output = format_security_requirements([req])

        assert "2.1.1" in output
        assert "Password Security" in output
        assert "Level 1" in output
        assert "example code" in output

    def test_format_scan_results_passed(self):
        """Test formatting scan results with no findings."""
        output = format_scan_results([])

        assert "PASSED" in output
        assert "No security vulnerabilities" in output

    def test_format_scan_results_failed(self):
        """Test formatting scan results with findings."""
        result = ScanResult(
            severity=SeverityLevel.HIGH,
            vulnerability_type="SQL Injection",
            asvs_requirements=["5.3.4"],
            location=Location(
                line=10,
                filename="app.py",
                code_snippet="cursor.execute(f'...')",
            ),
            message="SQL injection detected",
            remediation="Use parameterized queries",
            scanner="semgrep",
        )

        output = format_scan_results([result])

        assert "FAILED" in output
        assert "SQL Injection" in output
        assert "5.3.4" in output
        assert "app.py" in output
        assert "parameterized queries" in output

    def test_format_fix_suggestion(self):
        """Test formatting fix suggestion."""
        fix = FixSuggestion(
            vulnerable_code="bad code",
            secure_code="good code",
            explanation="This is why",
            asvs_requirements=["5.3.4"],
            security_benefits=["Prevents attacks"],
        )

        output = format_fix_suggestion(fix)

        assert "bad code" in output
        assert "good code" in output
        assert "This is why" in output
        assert "5.3.4" in output
        assert "Prevents attacks" in output

    def test_format_includes_severity_icons(self):
        """Test that severity icons are included."""
        result = ScanResult(
            severity=SeverityLevel.CRITICAL,
            vulnerability_type="Test",
            location=Location(),
            message="Test",
            remediation="Test",
            scanner="test",
        )

        output = format_scan_results([result])
        assert "🔴" in output  # Critical icon


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

