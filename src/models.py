"""Pydantic data models for ASVS requirements and security scan results."""

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, ConfigDict


class SeverityLevel(str, Enum):
    """Severity levels for security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# CodeType enum removed in v2.0.0 - use direct category/chapter search instead


class ASVSRequirement(BaseModel):
    """Represents a single OWASP ASVS 5.0 security requirement from official JSON."""

    id: str = Field(..., description="ASVS requirement ID (e.g., 'V6.2.1')")
    level: int = Field(..., ge=1, le=3, description="ASVS level (1, 2, or 3)")
    category: str = Field(..., description="Section name (e.g., 'Password Security')")
    chapter: str = Field(..., description="Chapter name (e.g., 'Authentication')")
    requirement: str = Field(..., description="Full requirement text from official ASVS")
    cwe: Optional[list[str]] = Field(None, description="CWE IDs from official mapping (e.g., ['CWE-521'])")
    tags: list[str] = Field(
        default_factory=list, description="Searchable tags derived from chapter/section"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "V6.2.1",
                "level": 1,
                "category": "Password Security",
                "chapter": "Authentication",
                "requirement": "Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended.",
                "cwe": ["CWE-521"],
                "tags": ["authentication", "password_security"],
            }
        }
    )


class Location(BaseModel):
    """Location information for a security finding."""

    line: Optional[int] = Field(None, description="Line number where issue was found")
    column: Optional[int] = Field(None, description="Column number where issue was found")
    end_line: Optional[int] = Field(None, description="End line number")
    filename: Optional[str] = Field(None, description="Filename where issue was found")
    code_snippet: Optional[str] = Field(None, description="Relevant code snippet")


class ScanResult(BaseModel):
    """Result from a security scan."""

    severity: SeverityLevel = Field(..., description="Severity of the finding")
    vulnerability_type: str = Field(..., description="Type of vulnerability detected")
    asvs_requirements: list[str] = Field(
        default_factory=list, description="ASVS requirement IDs violated"
    )
    location: Location = Field(..., description="Location of the vulnerability")
    message: str = Field(..., description="Human-readable description of the issue")
    remediation: str = Field(..., description="How to fix the vulnerability")
    attack_vector: Optional[str] = Field(None, description="How this vulnerability can be exploited")
    scanner: str = Field(..., description="Scanner that detected this issue")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional scanner-specific metadata"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "severity": "HIGH",
                "vulnerability_type": "SQL Injection",
                "asvs_requirements": ["5.3.4", "5.3.5"],
                "location": {
                    "line": 42,
                    "column": 10,
                    "filename": "app.py",
                    "code_snippet": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                },
                "message": "SQL injection vulnerability detected",
                "remediation": "Use parameterized queries instead of string concatenation",
                "scanner": "semgrep",
            }
        }
    )


class FixSuggestion(BaseModel):
    """Suggestion for fixing a security vulnerability."""

    vulnerable_code: str = Field(..., description="Original vulnerable code")
    secure_code: str = Field(..., description="Secure alternative code")
    explanation: str = Field(..., description="Explanation of changes made")
    asvs_requirements: list[str] = Field(
        default_factory=list, description="ASVS requirements satisfied by this fix"
    )
    security_benefits: list[str] = Field(
        default_factory=list, description="Security benefits of this fix"
    )
    additional_considerations: Optional[str] = Field(
        None, description="Additional security considerations"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "vulnerable_code": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                "secure_code": 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                "explanation": "Replaced string formatting with parameterized query",
                "asvs_requirements": ["5.3.4"],
                "security_benefits": ["Prevents SQL injection attacks"],
            }
        }
    )


class SecurityRequirementsRequest(BaseModel):
    """Request for security requirements lookup."""

    category: Optional[str] = Field(None, description="ASVS category name (e.g., 'Password Security')")
    chapter: Optional[str] = Field(None, description="ASVS chapter name (e.g., 'Authentication')")
    query: Optional[str] = Field(None, description="Free-text search query")
    level: Optional[str] = Field(
        None, 
        description="ASVS level - '1', '2', '3' for exact match, or '1,2' for multiple levels"
    )
    language: Optional[str] = Field(None, description="Programming language")
    context: Optional[str] = Field(None, description="Additional context about the code")
    
    def model_post_init(self, __context):
        """Validate that at least one search parameter is provided."""
        if not any([self.category, self.chapter, self.query]):
            raise ValueError("At least one of 'category', 'chapter', or 'query' must be provided")
        if self.category and self.chapter:
            raise ValueError("'category' and 'chapter' are mutually exclusive")


class ScanCodeRequest(BaseModel):
    """Request to scan code for vulnerabilities."""

    code: str = Field(..., description="Code to analyze")
    language: str = Field(..., description="Programming language")
    filename: Optional[str] = Field(None, description="Filename for context")
    context: Optional[str] = Field(None, description="What the code is supposed to do")


class FixSuggestionRequest(BaseModel):
    """Request for fix suggestion."""

    vulnerable_code: str = Field(..., description="Code with security issue")
    vulnerability_type: str = Field(..., description="Type of vulnerability")
    language: str = Field(..., description="Programming language")
    context: Optional[str] = Field(None, description="Additional context")


class ScanSummary(BaseModel):
    """Summary of a security scan."""

    total_findings: int = Field(..., description="Total number of findings")
    critical: int = Field(0, description="Number of critical findings")
    high: int = Field(0, description="Number of high severity findings")
    medium: int = Field(0, description="Number of medium severity findings")
    low: int = Field(0, description="Number of low severity findings")
    info: int = Field(0, description="Number of informational findings")
    asvs_requirements_violated: list[str] = Field(
        default_factory=list, description="Unique ASVS requirements violated"
    )
    passed: bool = Field(..., description="Whether the scan passed (no critical/high findings)")

