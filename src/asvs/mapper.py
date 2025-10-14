"""Map security findings to ASVS requirement IDs."""

import logging
from typing import Optional

from ..models import CodeType

logger = logging.getLogger(__name__)


class ASVSMapper:
    """Map vulnerability types and CWEs to ASVS requirement IDs."""

    # Mapping of vulnerability types to ASVS requirement IDs
    VULNERABILITY_TO_ASVS = {
        # SQL Injection
        "sql_injection": ["5.3.4", "5.3.5"],
        "sqli": ["5.3.4", "5.3.5"],
        # XSS
        "xss": ["5.3.3", "5.3.10"],
        "cross_site_scripting": ["5.3.3", "5.3.10"],
        "reflected_xss": ["5.3.3", "5.3.10"],
        "stored_xss": ["5.3.3", "5.3.10"],
        "dom_xss": ["5.3.3", "5.3.10"],
        # Password Issues
        "weak_password": ["2.1.1", "2.1.7", "2.1.9"],
        "hardcoded_password": ["2.3.1", "14.3.3"],
        "password_in_code": ["2.3.1", "14.3.3"],
        # Cryptography
        "weak_crypto": ["6.2.2", "6.2.5"],
        "weak_cipher": ["6.2.2", "6.2.5"],
        "insecure_hash": ["6.2.2"],
        "weak_hash": ["6.2.2"],
        "md5": ["6.2.2"],
        "sha1": ["6.2.2"],
        "ecb_mode": ["6.2.5"],
        # Password Hashing
        "weak_password_hash": ["9.2.1"],
        "insecure_password_hash": ["9.2.1"],
        # Session Management
        "session_fixation": ["3.2.1"],
        "weak_session": ["3.2.2"],
        "session_in_url": ["3.1.1"],
        "missing_secure_flag": ["3.4.1"],
        "missing_httponly": ["3.4.2"],
        "missing_samesite": ["3.4.5"],
        # Authentication
        "brute_force": ["2.2.1"],
        "no_rate_limiting": ["2.2.1"],
        "weak_2fa": ["2.7.1"],
        # Secrets
        "hardcoded_secret": ["2.3.1", "14.3.3"],
        "api_key": ["2.3.1", "14.3.3"],
        "secret_in_code": ["2.3.1", "14.3.3"],
        # TLS/SSL
        "insecure_transport": ["9.1.2", "9.2.1"],
        "no_tls": ["9.1.2", "9.2.1"],
        "weak_tls": ["9.1.2"],
        # Input Validation
        "xxe": ["5.5.2"],
        "xml_external_entity": ["5.5.2"],
        "parameter_pollution": ["5.1.1"],
        "missing_input_validation": ["5.1.3"],
        # Output Encoding
        "missing_output_encoding": ["5.3.3"],
        "html_injection": ["5.2.1"],
        # CSP
        "missing_csp": ["5.3.10"],
        "weak_csp": ["5.3.10"],
        # Deserialization
        "insecure_deserialization": ["5.5.2"],
        # CSRF
        "csrf": ["3.4.5"],
        "missing_csrf": ["3.4.5"],
    }

    # Mapping of CWE IDs to ASVS requirement IDs
    CWE_TO_ASVS = {
        "CWE-89": ["5.3.4", "5.3.5"],  # SQL Injection
        "CWE-79": ["5.3.3", "5.3.10"],  # XSS
        "CWE-521": ["2.1.1", "2.1.7", "2.1.9"],  # Weak Password
        "CWE-327": ["6.2.2"],  # Weak Crypto
        "CWE-326": ["6.2.5"],  # Weak Cipher Mode
        "CWE-330": ["2.3.1"],  # Weak Random
        "CWE-916": ["9.2.1"],  # Weak Password Hash
        "CWE-384": ["3.2.1"],  # Session Fixation
        "CWE-598": ["3.1.1"],  # Session in URL
        "CWE-614": ["3.4.1"],  # Missing Secure Flag
        "CWE-1004": ["3.4.2"],  # Missing HttpOnly
        "CWE-352": ["3.4.5"],  # CSRF
        "CWE-307": ["2.2.1"],  # No Rate Limiting
        "CWE-287": ["2.7.1"],  # Weak Authentication
        "CWE-319": ["9.1.2", "9.2.1"],  # Insecure Transport
        "CWE-611": ["5.5.2"],  # XXE
        "CWE-20": ["5.1.3"],  # Missing Input Validation
        "CWE-116": ["5.2.1"],  # Improper Encoding
        "CWE-1021": ["5.3.10"],  # Missing CSP
        "CWE-235": ["5.1.1"],  # Parameter Pollution
        "CWE-640": ["2.5.2"],  # Weak Credential Recovery
        "CWE-613": ["3.3.1", "3.3.2"],  # Session Management
        "CWE-310": ["6.2.1"],  # Crypto Error Handling
        "CWE-323": ["6.2.6"],  # IV Reuse
        "CWE-299": ["9.2.4"],  # Certificate Validation
        "CWE-316": ["14.3.3"],  # Memory Disclosure
    }

    # Mapping of code types to relevant ASVS categories
    CODE_TYPE_TO_CATEGORIES = {
        CodeType.AUTHENTICATION: ["Password Security", "General Authenticator Security"],
        CodeType.SESSION_MANAGEMENT: [
            "Fundamental Session Management",
            "Session Binding",
            "Session Logout and Timeout",
            "Cookie-based Session Management",
        ],
        CodeType.ACCESS_CONTROL: ["Access Control"],
        CodeType.INPUT_VALIDATION: [
            "Input Validation",
            "Sanitization and Sandboxing",
            "Output Encoding and Injection Prevention",
        ],
        CodeType.CRYPTOGRAPHY: ["Algorithms", "Communications Security"],
        CodeType.ERROR_HANDLING: ["Error Handling"],
        CodeType.DATA_PROTECTION: ["Data Protection", "Unintended Security Disclosure"],
        CodeType.COMMUNICATION: ["Communications Security", "Server Communications Security"],
        CodeType.MALICIOUS_CODE: ["Malicious Code"],
    }

    def map_vulnerability_to_asvs(self, vulnerability_type: str) -> list[str]:
        """
        Map a vulnerability type to ASVS requirement IDs.

        Args:
            vulnerability_type: Type of vulnerability (e.g., "sql_injection")

        Returns:
            List of ASVS requirement IDs
        """
        vuln_type_lower = vulnerability_type.lower().replace("-", "_").replace(" ", "_")
        asvs_ids = self.VULNERABILITY_TO_ASVS.get(vuln_type_lower, [])

        if not asvs_ids:
            logger.debug(f"No ASVS mapping found for vulnerability type: {vulnerability_type}")

        return asvs_ids

    def map_cwe_to_asvs(self, cwe: str | list[str]) -> list[str]:
        """
        Map a CWE ID (or list of CWE IDs) to ASVS requirement IDs.

        Args:
            cwe: CWE ID (e.g., "CWE-89" or "89") or list of CWE IDs

        Returns:
            List of ASVS requirement IDs
        """
        # Handle list of CWEs
        if isinstance(cwe, list):
            all_asvs_ids = []
            for cwe_item in cwe:
                all_asvs_ids.extend(self.map_cwe_to_asvs(cwe_item))
            return list(set(all_asvs_ids))  # Remove duplicates
        
        # Handle None or empty string
        if not cwe:
            return []
        
        # Normalize CWE format
        if not cwe.startswith("CWE-"):
            cwe = f"CWE-{cwe}"

        asvs_ids = self.CWE_TO_ASVS.get(cwe, [])

        if not asvs_ids:
            logger.debug(f"No ASVS mapping found for CWE: {cwe}")

        return asvs_ids

    def map_code_type_to_categories(self, code_type: CodeType) -> list[str]:
        """
        Map a code type to relevant ASVS categories.

        Args:
            code_type: Type of code pattern

        Returns:
            List of ASVS categories
        """
        return self.CODE_TYPE_TO_CATEGORIES.get(code_type, [])

    def map_finding_to_asvs(
        self,
        vulnerability_type: Optional[str] = None,
        cwe: Optional[str] = None,
    ) -> list[str]:
        """
        Map a security finding to ASVS requirement IDs.

        Combines results from both vulnerability type and CWE mappings.

        Args:
            vulnerability_type: Type of vulnerability
            cwe: CWE ID

        Returns:
            List of unique ASVS requirement IDs
        """
        asvs_ids: set[str] = set()

        if vulnerability_type:
            asvs_ids.update(self.map_vulnerability_to_asvs(vulnerability_type))

        if cwe:
            asvs_ids.update(self.map_cwe_to_asvs(cwe))

        return sorted(asvs_ids)


# Global mapper instance
_mapper: Optional[ASVSMapper] = None


def get_asvs_mapper() -> ASVSMapper:
    """Get global ASVS mapper instance."""
    global _mapper
    if _mapper is None:
        _mapper = ASVSMapper()
    return _mapper

