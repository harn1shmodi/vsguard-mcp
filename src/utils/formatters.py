"""Format output for optimal LLM comprehension."""

import logging
from typing import Optional

from ..models import ASVSRequirement, FixSuggestion, ScanResult, ScanSummary, SeverityLevel

logger = logging.getLogger(__name__)


def format_security_requirements(
    requirements: list[ASVSRequirement],
    context: Optional[str] = None,
    include_examples: bool = True,
) -> str:
    """
    Format ASVS requirements in a clear, actionable way for LLMs.

    Args:
        requirements: List of ASVS requirements
        context: Optional context about why these requirements are relevant
        include_examples: Whether to include code examples

    Returns:
        Formatted string optimized for LLM consumption
    """
    if not requirements:
        return "No relevant ASVS requirements found."

    # Sort by level (Level 1 first) then by ID
    sorted_reqs = sorted(requirements, key=lambda r: (r.level, r.id))

    output = ["# OWASP ASVS Security Requirements\n"]

    if context:
        output.append(f"**Context:** {context}\n")

    output.append(f"**Total Requirements:** {len(requirements)}\n")

    # Group by level
    by_level: dict[int, list[ASVSRequirement]] = {}
    for req in sorted_reqs:
        if req.level not in by_level:
            by_level[req.level] = []
        by_level[req.level].append(req)

    for level in sorted([1, 2, 3]):
        if level not in by_level:
            continue

        level_reqs = by_level[level]
        output.append(f"\n## Level {level} Requirements ({len(level_reqs)})")
        output.append(
            f"*Level {level}: {'Baseline security' if level == 1 else 'Standard security' if level == 2 else 'High security'}*\n"
        )

        for req in level_reqs:
            output.append(f"### {req.id}: {req.category}")
            output.append(f"**Requirement:** {req.requirement}\n")

            if req.cwe:
                output.append(f"**CWE Mapping:** {req.cwe}")

            output.append(f"**Description:**")
            output.append(req.description)

            output.append(f"\n**Implementation Guide:**")
            output.append(req.implementation_guide)

            if include_examples and req.code_examples:
                output.append(f"\n**Code Examples:**")
                for i, example in enumerate(req.code_examples, 1):
                    output.append(f"```")
                    output.append(example.strip())
                    output.append(f"```")

            output.append("\n---\n")

    return "\n".join(output)


def format_scan_results(
    results: list[ScanResult],
    show_all: bool = True,
) -> str:
    """
    Format scan results with clear prioritization and actionable guidance.

    Args:
        results: List of scan results
        show_all: Whether to show all findings or only critical/high

    Returns:
        Formatted string optimized for LLM consumption
    """
    if not results:
        return "✅ **SCAN PASSED**\n\nNo security vulnerabilities detected."

    # Generate summary
    summary = _generate_summary(results)

    output = []

    # Executive summary
    if summary.passed:
        output.append("✅ **SCAN PASSED** (with informational findings)")
    else:
        output.append("❌ **SCAN FAILED**")

    output.append(f"\n**Total Findings:** {summary.total_findings}")
    if summary.critical > 0:
        output.append(f"- 🔴 **CRITICAL:** {summary.critical}")
    if summary.high > 0:
        output.append(f"- 🟠 **HIGH:** {summary.high}")
    if summary.medium > 0:
        output.append(f"- 🟡 **MEDIUM:** {summary.medium}")
    if summary.low > 0:
        output.append(f"- 🔵 **LOW:** {summary.low}")
    if summary.info > 0:
        output.append(f"- ⚪ **INFO:** {summary.info}")

    if summary.asvs_requirements_violated:
        output.append(
            f"\n**ASVS Requirements Violated:** {', '.join(summary.asvs_requirements_violated)}"
        )

    output.append("\n---\n")

    # Sort by severity
    severity_order = {
        SeverityLevel.CRITICAL: 0,
        SeverityLevel.HIGH: 1,
        SeverityLevel.MEDIUM: 2,
        SeverityLevel.LOW: 3,
        SeverityLevel.INFO: 4,
    }
    sorted_results = sorted(results, key=lambda r: severity_order.get(r.severity, 5))

    # Filter if needed
    if not show_all:
        sorted_results = [
            r for r in sorted_results if r.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
        ]

    # Detailed findings
    output.append("## Detailed Findings\n")

    for i, result in enumerate(sorted_results, 1):
        severity_icon = _get_severity_icon(result.severity)

        output.append(f"### {i}. {severity_icon} {result.vulnerability_type}")
        output.append(f"**Severity:** {result.severity.value}")

        if result.asvs_requirements:
            output.append(f"**ASVS Requirements:** {', '.join(result.asvs_requirements)}")

        output.append(f"\n**Issue:**")
        output.append(result.message)

        if result.location.filename:
            location_parts = [result.location.filename]
            if result.location.line:
                location_parts.append(f"line {result.location.line}")
            output.append(f"\n**Location:** {':'.join(location_parts)}")

        if result.location.code_snippet:
            output.append(f"\n**Vulnerable Code:**")
            output.append("```")
            output.append(result.location.code_snippet.strip())
            output.append("```")

        if result.attack_vector:
            output.append(f"\n**Attack Vector:**")
            output.append(result.attack_vector)

        output.append(f"\n**Remediation:**")
        output.append(result.remediation)

        output.append(f"\n**Detected by:** {result.scanner}")

        output.append("\n---\n")

    return "\n".join(output)


def format_fix_suggestion(fix: FixSuggestion) -> str:
    """
    Format fix suggestion with side-by-side comparison.

    Args:
        fix: Fix suggestion

    Returns:
        Formatted string optimized for LLM consumption
    """
    output = ["# Security Fix Suggestion\n"]

    if fix.asvs_requirements:
        output.append(f"**ASVS Requirements Addressed:** {', '.join(fix.asvs_requirements)}\n")

    output.append("## ❌ Vulnerable Code")
    output.append("```")
    output.append(fix.vulnerable_code.strip())
    output.append("```\n")

    output.append("## ✅ Secure Code")
    output.append("```")
    output.append(fix.secure_code.strip())
    output.append("```\n")

    output.append("## 📝 Explanation")
    output.append(fix.explanation)

    if fix.security_benefits:
        output.append("\n## 🛡️ Security Benefits")
        for benefit in fix.security_benefits:
            output.append(f"- {benefit}")

    if fix.additional_considerations:
        output.append("\n## ⚠️ Additional Considerations")
        output.append(fix.additional_considerations)

    return "\n".join(output)


def _generate_summary(results: list[ScanResult]) -> ScanSummary:
    """Generate summary statistics from scan results."""
    summary = ScanSummary(
        total_findings=len(results),
        critical=0,
        high=0,
        medium=0,
        low=0,
        info=0,
        asvs_requirements_violated=[],
        passed=True,
    )

    asvs_set: set[str] = set()

    for result in results:
        # Count by severity
        if result.severity == SeverityLevel.CRITICAL:
            summary.critical += 1
            summary.passed = False
        elif result.severity == SeverityLevel.HIGH:
            summary.high += 1
            summary.passed = False
        elif result.severity == SeverityLevel.MEDIUM:
            summary.medium += 1
        elif result.severity == SeverityLevel.LOW:
            summary.low += 1
        elif result.severity == SeverityLevel.INFO:
            summary.info += 1

        # Collect ASVS IDs
        asvs_set.update(result.asvs_requirements)

    summary.asvs_requirements_violated = sorted(asvs_set)

    return summary


def _get_severity_icon(severity: SeverityLevel) -> str:
    """Get emoji icon for severity level."""
    icons = {
        SeverityLevel.CRITICAL: "🔴",
        SeverityLevel.HIGH: "🟠",
        SeverityLevel.MEDIUM: "🟡",
        SeverityLevel.LOW: "🔵",
        SeverityLevel.INFO: "⚪",
    }
    return icons.get(severity, "⚫")


def format_requirement_summary(requirements: list[ASVSRequirement]) -> str:
    """
    Format a brief summary of requirements (for large lists).

    Args:
        requirements: List of ASVS requirements

    Returns:
        Brief summary string
    """
    if not requirements:
        return "No requirements found."

    by_category: dict[str, int] = {}
    by_level: dict[int, int] = {}

    for req in requirements:
        by_category[req.category] = by_category.get(req.category, 0) + 1
        by_level[req.level] = by_level.get(req.level, 0) + 1

    output = [f"Found {len(requirements)} ASVS requirements:\n"]

    output.append("**By Level:**")
    for level in sorted(by_level.keys()):
        output.append(f"- Level {level}: {by_level[level]}")

    output.append("\n**By Category:**")
    for category in sorted(by_category.keys()):
        output.append(f"- {category}: {by_category[category]}")

    return "\n".join(output)

