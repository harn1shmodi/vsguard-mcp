"""Sample secure code examples."""

# SQL Injection - Secure
def login_secure(username, password):
    """Secure against SQL injection using parameterized queries."""
    import sqlite3
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    # SECURE: Parameterized query
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    return cursor.fetchone()


# XSS - Secure
def display_user_input_secure(user_input):
    """Secure against XSS using sanitization."""
    import bleach
    
    ALLOWED_TAGS = ['p', 'br', 'strong', 'em']
    ALLOWED_ATTRS = {}
    
    # SECURE: Sanitize HTML
    clean_input = bleach.clean(
        user_input,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRS,
        strip=True
    )
    return clean_input


# Strong password validation
def validate_password_secure(password):
    """Strong password validation following ASVS."""
    import pwnedpasswords
    
    # ASVS 2.1.1: Minimum 12 characters
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    
    # ASVS 2.1.7: Check against breached passwords
    if pwnedpasswords.check(password) > 0:
        raise ValueError("Password has been compromised")
    
    return True


# Secure password hashing
def hash_password_secure(password):
    """Secure password hashing with Argon2id."""
    from passlib.hash import argon2
    
    # SECURE: Argon2id (recommended)
    return argon2.hash(password)


# Secure secret management
def connect_to_api_secure():
    """Secure API key from environment."""
    import os
    
    # SECURE: Load from environment variable
    API_KEY = os.environ.get("API_KEY")
    if not API_KEY:
        raise ValueError("API_KEY environment variable not set")
    
    return f"Using key from environment"


# Strong cryptography
def encrypt_data_secure(data, key):
    """Secure encryption with AES-GCM."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os
    
    # SECURE: AES-GCM authenticated encryption
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, data, None)
    return ciphertext, iv


# Session regeneration
def login_with_regeneration(username, password):
    """Secure login with session regeneration."""
    from flask import session
    
    if verify_credentials(username, password):
        # SECURE: Regenerate session
        session.clear()
        session['user_id'] = get_user_id(username)
        session['authenticated'] = True
        return True
    return False


# Secure cookie
def set_session_cookie_secure(response, session_id):
    """Secure cookie configuration."""
    # SECURE: All security flags set
    response.set_cookie(
        'session',
        session_id,
        secure=True,      # Only over HTTPS
        httponly=True,    # No JavaScript access
        samesite='Lax',   # CSRF protection
        max_age=3600      # 1 hour
    )
    return response


# XXE prevention
def parse_xml_secure(xml_string):
    """Secure XML parsing with defusedxml."""
    import defusedxml.ElementTree as ET
    
    # SECURE: defusedxml prevents XXE
    tree = ET.fromstring(xml_string)
    return tree


def verify_credentials(username, password):
    """Mock credential verification."""
    return True


def get_user_id(username):
    """Mock get user ID."""
    return 123

