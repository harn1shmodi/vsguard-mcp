"""Generate secure code fixes for vulnerabilities."""

import logging
from typing import Optional

from ..asvs.mapper import get_asvs_mapper
from ..models import FixSuggestion
from .templates import get_fix_template

logger = logging.getLogger(__name__)


class FixGenerator:
    """Generate secure code alternatives for vulnerabilities."""

    def __init__(self) -> None:
        """Initialize fix generator."""
        self.mapper = get_asvs_mapper()

    async def generate_fix(
        self,
        vulnerable_code: str,
        vulnerability_type: str,
        language: str,
        context: Optional[str] = None,
    ) -> FixSuggestion:
        """
        Generate a secure code alternative for a vulnerability.

        Args:
            vulnerable_code: Code with security issue
            vulnerability_type: Type of vulnerability
            language: Programming language
            context: Optional additional context

        Returns:
            Fix suggestion with secure code alternative
        """
        logger.info(f"Generating fix for {vulnerability_type} in {language}")

        # Get fix template
        template = get_fix_template(vulnerability_type, language)

        if template:
            # Use template
            secure_code = template["secure"]
            explanation = template["explanation"]
            asvs_requirements = template.get("asvs_requirements", [])

            # Build security benefits list
            security_benefits = []
            if "sql_injection" in vulnerability_type.lower():
                security_benefits.append("Prevents SQL injection attacks")
                security_benefits.append("Separates code from data")
            elif "xss" in vulnerability_type.lower():
                security_benefits.append("Prevents cross-site scripting (XSS) attacks")
                security_benefits.append("Protects users from malicious scripts")
            elif "weak_password" in vulnerability_type.lower():
                security_benefits.append("Resists brute force attacks")
                security_benefits.append("Protects against credential stuffing")
            elif "weak_crypto" in vulnerability_type.lower():
                security_benefits.append("Uses modern, secure cryptographic algorithms")
                security_benefits.append("Provides confidentiality and integrity")
            elif "session" in vulnerability_type.lower():
                security_benefits.append("Prevents session hijacking")
                security_benefits.append("Mitigates CSRF attacks")

            # Additional considerations
            additional_considerations = None
            if "sql_injection" in vulnerability_type.lower():
                additional_considerations = (
                    "- Also validate and sanitize input\n"
                    "- Use principle of least privilege for database users\n"
                    "- Consider using an ORM for additional safety"
                )
            elif "xss" in vulnerability_type.lower():
                additional_considerations = (
                    "- Implement Content Security Policy (CSP) header\n"
                    "- Validate input on the server side\n"
                    "- Use auto-escaping templates when possible"
                )
            elif "weak_password" in vulnerability_type.lower():
                additional_considerations = (
                    "- Implement rate limiting on login attempts\n"
                    "- Consider multi-factor authentication (MFA)\n"
                    "- Use breach detection services (HaveIBeenPwned)"
                )

        else:
            # Generate generic fix
            logger.warning(f"No template found for {vulnerability_type} in {language}")

            # Map to ASVS requirements
            asvs_requirements = self.mapper.map_vulnerability_to_asvs(vulnerability_type)

            secure_code = self._generate_generic_fix(vulnerability_type, language)
            explanation = f"Replace vulnerable code with secure alternative that addresses {vulnerability_type}."
            security_benefits = ["Addresses security vulnerability"]
            additional_considerations = "Consult ASVS requirements and security best practices for your language."

        return FixSuggestion(
            vulnerable_code=vulnerable_code,
            secure_code=secure_code,
            explanation=explanation,
            asvs_requirements=asvs_requirements,
            security_benefits=security_benefits,
            additional_considerations=additional_considerations,
        )

    def _generate_generic_fix(self, vulnerability_type: str, language: str) -> str:
        """Generate a generic fix message when no template is available."""
        return f"""# Secure implementation needed for {vulnerability_type}

# Please refer to OWASP ASVS requirements and implement:
# 1. Input validation and sanitization
# 2. Secure defaults and configurations
# 3. Defense-in-depth security controls

# For specific guidance, use: check_security_requirements tool
# with code_type related to {vulnerability_type}

# Example resources:
# - OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
# - OWASP Cheat Sheets: https://cheatsheetseries.owasp.org/
# - Language-specific security guides for {language}
"""

