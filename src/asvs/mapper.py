"""Map security findings to ASVS requirement IDs (ASVS 5.0)."""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class ASVSMapper:
    """Map vulnerability types and CWEs to ASVS 5.0 requirement IDs."""

    # Mapping of vulnerability types to ASVS 5.0 requirement IDs
    VULNERABILITY_TO_ASVS = {
        # SQL Injection - moved to V1 (Encoding and Sanitization)
        "sql_injection": ["V1.2.4"],
        "sqli": ["V1.2.4"],
        
        # XSS - moved to V1 (Encoding and Sanitization)
        "xss": ["V1.2.1", "V1.2.3"],
        "cross_site_scripting": ["V1.2.1", "V1.2.3"],
        "reflected_xss": ["V1.2.1"],
        "stored_xss": ["V1.2.1"],
        "dom_xss": ["V3.2.2"],
        
        # Command Injection - V1
        "command_injection": ["V1.2.5"],
        "os_command_injection": ["V1.2.5"],
        
        # XXE - V1
        "xxe": ["V1.5.1"],
        "xml_external_entity": ["V1.5.1"],
        
        # Deserialization - V1
        "insecure_deserialization": ["V1.5.2"],
        
        # Password Issues - moved to V6 (Authentication)
        "weak_password": ["V6.2.1", "V6.2.4", "V6.2.5"],
        "hardcoded_password": ["V6.4.1", "V13.3.1"],
        "password_in_code": ["V6.4.1", "V13.3.1"],
        
        # Authentication - V6
        "brute_force": ["V6.3.1"],
        "no_rate_limiting": ["V6.3.1"],
        "weak_2fa": ["V6.6.1"],
        "weak_authentication": ["V6.3.2"],
        
        # Password hints/questions - V6
        "security_questions": ["V6.4.2"],
        "password_hints": ["V6.4.2"],
        
        # Cryptography - moved to V11
        "weak_crypto": ["V11.3.1", "V11.3.2"],
        "weak_cipher": ["V11.3.1"],
        "insecure_hash": ["V11.4.1"],
        "weak_hash": ["V11.4.1"],
        "md5": ["V11.4.1"],
        "sha1": ["V11.4.1"],
        "ecb_mode": ["V11.3.1"],
        
        # Password Hashing - V11
        "weak_password_hash": ["V11.4.2"],
        "insecure_password_hash": ["V11.4.2"],
        
        # Random Numbers - V11
        "weak_random": ["V11.5.1"],
        "predictable_random": ["V11.5.1"],
        
        # Session Management - moved to V7
        "session_fixation": ["V7.2.4"],
        "weak_session": ["V7.2.3"],
        "session_in_url": ["V3.3.1"],  # Cookie-related in V3
        "missing_secure_flag": ["V3.3.1"],
        "missing_httponly": ["V3.3.4"],
        "missing_samesite": ["V3.3.2"],
        
        # CSRF - V3
        "csrf": ["V3.5.1"],
        "missing_csrf": ["V3.5.1"],
        
        # Secrets - V13
        "hardcoded_secret": ["V13.3.1"],
        "api_key": ["V13.3.1"],
        "secret_in_code": ["V13.3.1"],
        
        # TLS/SSL - moved to V12
        "insecure_transport": ["V12.2.1"],
        "no_tls": ["V12.2.1"],
        "weak_tls": ["V12.1.1"],
        
        # Input Validation - V2
        "parameter_pollution": ["V2.2.1"],
        "missing_input_validation": ["V2.2.1"],
        
        # Output Encoding - V1
        "missing_output_encoding": ["V1.2.1"],
        "html_injection": ["V1.2.1"],
        
        # CSP - V3
        "missing_csp": ["V3.4.3"],
        "weak_csp": ["V3.4.3"],
        
        # File Upload - V5
        "file_upload": ["V5.2.1", "V5.2.2"],
        "malicious_file": ["V5.4.3"],
        
        # Path Traversal - V5
        "path_traversal": ["V5.3.2"],
        
        # SSRF - V1
        "ssrf": ["V1.3.6"],
    }

    # Mapping of CWE IDs to ASVS 5.0 requirement IDs
    CWE_TO_ASVS = {
        # Injection Vulnerabilities
        "CWE-89": ["V1.2.4"],  # SQL Injection
        "CWE-79": ["V1.2.1", "V1.2.3"],  # XSS
        "CWE-78": ["V1.2.5"],  # OS Command Injection
        "CWE-77": ["V1.2.5"],  # Command Injection
        "CWE-611": ["V1.5.1"],  # XXE
        "CWE-502": ["V1.5.2"],  # Deserialization
        "CWE-917": ["V1.2.4"],  # Expression Language Injection
        "CWE-918": ["V1.3.6"],  # SSRF
        
        # Authentication & Password (V6)
        "CWE-521": ["V6.2.1", "V6.2.4"],  # Weak Password
        "CWE-798": ["V6.4.1", "V13.3.1"],  # Hardcoded Credentials
        "CWE-307": ["V6.3.1"],  # Improper Auth (Brute Force)
        "CWE-287": ["V6.3.2"],  # Improper Authentication
        "CWE-640": ["V6.4.2"],  # Weak Password Recovery
        "CWE-620": ["V6.2.5"],  # Unverified Password Change
        
        # Session Management (V7)
        "CWE-384": ["V7.2.4"],  # Session Fixation
        "CWE-613": ["V7.2.3"],  # Insufficient Session Expiration
        "CWE-598": ["V3.3.1"],  # GET with Sensitive Data
        
        # Cookie Security (V3)
        "CWE-614": ["V3.3.1"],  # Sensitive Cookie Without Secure
        "CWE-1004": ["V3.3.4"],  # Sensitive Cookie Without HttpOnly
        "CWE-352": ["V3.5.1"],  # CSRF
        
        # Cryptography (V11)
        "CWE-327": ["V11.3.1", "V11.4.1"],  # Broken Crypto
        "CWE-326": ["V11.3.1"],  # Inadequate Encryption Strength
        "CWE-330": ["V11.5.1"],  # Weak Random
        "CWE-338": ["V11.5.1"],  # Weak PRNG
        "CWE-916": ["V11.4.2"],  # Weak Password Hash
        "CWE-759": ["V11.4.2"],  # Salted Hash without Salt
        
        # TLS/Transport (V12)
        "CWE-319": ["V12.2.1"],  # Cleartext Transmission
        "CWE-295": ["V12.3.2"],  # Improper Certificate Validation
        "CWE-310": ["V12.1.1"],  # Cryptographic Issues
        
        # Input Validation (V2)
        "CWE-20": ["V2.2.1"],  # Improper Input Validation
        "CWE-116": ["V1.2.1"],  # Improper Encoding
        "CWE-235": ["V2.2.1"],  # Parameter Issues
        
        # Output Encoding (V1)
        "CWE-116": ["V1.2.1"],  # Improper Output Encoding
        
        # File Handling (V5)
        "CWE-434": ["V5.2.1"],  # Unrestricted File Upload
        "CWE-73": ["V5.3.2"],  # Path Traversal
        "CWE-22": ["V5.3.2"],  # Path Traversal
        
        # Security Headers (V3)
        "CWE-1021": ["V3.4.3"],  # Missing CSP
        "CWE-16": ["V3.4.4"],  # Configuration
        
        # Authorization (V8)
        "CWE-285": ["V8.2.1"],  # Improper Authorization
        "CWE-639": ["V8.2.2"],  # Insecure Direct Object Reference
        
        # Data Protection (V14)
        "CWE-312": ["V14.3.3"],  # Cleartext Storage
        "CWE-311": ["V14.2.1"],  # Missing Encryption
        "CWE-200": ["V13.4.2"],  # Information Exposure
        
        # Secrets Management (V13)
        "CWE-798": ["V13.3.1"],  # Hardcoded Credentials
        "CWE-257": ["V13.3.1"],  # Storing Passwords
        
        # Memory Safety (V1)
        "CWE-120": ["V1.4.1"],  # Buffer Overflow
        "CWE-119": ["V1.4.1"],  # Buffer Errors
        
        # Integer Issues (V1)
        "CWE-190": ["V1.4.2"],  # Integer Overflow
    }

    # CODE_TYPE_TO_CATEGORIES removed in v2.0.0 - use direct category/chapter search instead

    def map_vulnerability_to_asvs(self, vulnerability_type: str) -> list[str]:
        """
        Map a vulnerability type to ASVS 5.0 requirement IDs.

        Args:
            vulnerability_type: Type of vulnerability (e.g., "sql_injection")

        Returns:
            List of ASVS requirement IDs (e.g., ["V1.2.4"])
        """
        vuln_type_lower = vulnerability_type.lower().replace("-", "_").replace(" ", "_")
        asvs_ids = self.VULNERABILITY_TO_ASVS.get(vuln_type_lower, [])

        if not asvs_ids:
            logger.debug(f"No ASVS mapping found for vulnerability type: {vulnerability_type}")

        return asvs_ids

    def map_cwe_to_asvs(self, cwe: str | list[str]) -> list[str]:
        """
        Map a CWE ID (or list of CWE IDs) to ASVS 5.0 requirement IDs.

        Args:
            cwe: CWE ID (e.g., "CWE-89" or "89") or list of CWE IDs

        Returns:
            List of ASVS requirement IDs (e.g., ["V1.2.4"])
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

    # map_code_type_to_categories removed in v2.0.0 - use ASVSRequirementCollection search methods instead

    def map_finding_to_asvs(
        self,
        vulnerability_type: Optional[str] = None,
        cwe: Optional[str] = None,
    ) -> list[str]:
        """
        Map a security finding to ASVS 5.0 requirement IDs.

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
