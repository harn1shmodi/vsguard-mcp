"""Sample vulnerable code for testing."""

# SQL Injection vulnerabilities
def login_vulnerable(username, password):
    """Vulnerable to SQL injection."""
    import sqlite3
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    # VULNERABLE: String concatenation
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    return cursor.fetchone()


# XSS vulnerability
def display_user_input_vulnerable(user_input):
    """Vulnerable to XSS."""
    from flask import Markup
    
    # VULNERABLE: Marking untrusted input as safe
    return Markup(user_input)


# Weak password validation
def validate_password_weak(password):
    """Weak password validation."""
    # VULNERABLE: Too short
    if len(password) < 6:
        raise ValueError("Password too short")
    return True


# Weak password hashing
def hash_password_weak(password):
    """Weak password hashing."""
    import hashlib
    
    # VULNERABLE: MD5 is not suitable for passwords
    return hashlib.md5(password.encode()).hexdigest()


# Hardcoded secrets
def connect_to_api():
    """Hardcoded API key."""
    # VULNERABLE: Hardcoded secret
    API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
    return f"Using key: {API_KEY}"


# Weak cryptography
def encrypt_data_weak(data, key):
    """Weak encryption."""
    from Crypto.Cipher import DES
    
    # VULNERABLE: DES is deprecated
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)


# Missing session regeneration
def login_no_regeneration(username, password):
    """Missing session regeneration."""
    from flask import session
    
    if verify_credentials(username, password):
        # VULNERABLE: No session regeneration
        session['user_id'] = get_user_id(username)
        return True
    return False


# Insecure cookie
def set_session_cookie_insecure(response, session_id):
    """Insecure cookie configuration."""
    # VULNERABLE: Missing security flags
    response.set_cookie('session', session_id)
    return response


# XXE vulnerability
def parse_xml_vulnerable(xml_string):
    """Vulnerable to XXE."""
    import xml.etree.ElementTree as ET
    
    # VULNERABLE: Standard parser susceptible to XXE
    tree = ET.fromstring(xml_string)
    return tree


def verify_credentials(username, password):
    """Mock credential verification."""
    return True


def get_user_id(username):
    """Mock get user ID."""
    return 123

