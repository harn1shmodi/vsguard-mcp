"""Utility functions for ASVS ID conversions and transformations."""


def asvs_to_cwe_key(asvs_id: str) -> str:
    """
    Convert ASVS 5.0 ID format to CWE mapping key format.
    
    Args:
        asvs_id: ASVS ID in format "V1.2.4"
        
    Returns:
        CWE mapping key in format "v5.0.be-1.2.4"
        
    Example:
        >>> asvs_to_cwe_key("V1.2.4")
        "v5.0.be-1.2.4"
    """
    if not asvs_id.startswith('V'):
        raise ValueError(f"Invalid ASVS ID format: {asvs_id}. Expected format: V1.2.4")
    
    # Remove 'V' prefix and convert to lowercase
    numeric_part = asvs_id[1:]
    return f"v5.0.be-{numeric_part}"


def cwe_key_to_asvs(cwe_key: str) -> str:
    """
    Convert CWE mapping key format to ASVS 5.0 ID format.
    
    Args:
        cwe_key: CWE mapping key in format "v5.0.be-1.2.4"
        
    Returns:
        ASVS ID in format "V1.2.4"
        
    Example:
        >>> cwe_key_to_asvs("v5.0.be-1.2.4")
        "V1.2.4"
    """
    if not cwe_key.startswith('v5.0.be-'):
        raise ValueError(f"Invalid CWE key format: {cwe_key}. Expected format: v5.0.be-1.2.4")
    
    # Remove prefix and add 'V'
    numeric_part = cwe_key.replace('v5.0.be-', '')
    return f"V{numeric_part}"


def normalize_chapter_name(name: str) -> str:
    """
    Normalize chapter/section name to tag format.
    
    Args:
        name: Chapter or section name
        
    Returns:
        Normalized tag (lowercase, underscores)
        
    Example:
        >>> normalize_chapter_name("Encoding and Sanitization")
        "encoding_and_sanitization"
    """
    return name.lower().replace(' ', '_').replace('-', '_')


def generate_tags(chapter: str, section: str) -> list[str]:
    """
    Generate searchable tags from chapter and section names.
    
    Args:
        chapter: Chapter name (e.g., "Authentication")
        section: Section name (e.g., "Password Security")
        
    Returns:
        List of unique tags
        
    Example:
        >>> generate_tags("Authentication", "Password Security")
        ["authentication", "password_security"]
    """
    tags = []
    
    for name in [chapter, section]:
        tag = normalize_chapter_name(name)
        if tag not in tags:
            tags.append(tag)
    
    return tags


