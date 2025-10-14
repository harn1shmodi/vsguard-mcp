"""Secure code templates for common vulnerabilities."""

from typing import Optional

# Fix templates organized by vulnerability type and language
FIX_TEMPLATES = {
    "sql_injection": {
        "python": {
            "title": "SQL Injection Prevention (ASVS 5.3.4)",
            "vulnerable": """# Vulnerable: String concatenation
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")""",
            "secure": """# Secure: Parameterized queries
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))

# Or with SQLAlchemy ORM:
from sqlalchemy import select
stmt = select(User).where(User.username == username)
user = session.execute(stmt).scalar_one_or_none()""",
            "explanation": "Use parameterized queries (prepared statements) instead of string concatenation. This ensures user input is treated as data, not code.",
            "asvs_requirements": ["5.3.4", "5.3.5"],
        },
        "javascript": {
            "title": "SQL Injection Prevention (ASVS 5.3.4)",
            "vulnerable": r"""// Vulnerable: String concatenation
const query = `SELECT * FROM users WHERE id = ${userId}`;
db.query(query);""",
            "secure": """// Secure: Parameterized queries
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [userId]);

// Or with ORM (Sequelize):
const user = await User.findOne({ where: { id: userId } });""",
            "explanation": "Use parameterized queries with placeholders. ORMs like Sequelize handle this automatically.",
            "asvs_requirements": ["5.3.4", "5.3.5"],
        },
    },
    "xss": {
        "python": {
            "title": "XSS Prevention (ASVS 5.3.3)",
            "vulnerable": """# Vulnerable: Marking user input as safe
from flask import Markup
output = Markup(user_input)  # Bypasses auto-escaping""",
            "secure": """# Secure Option 1: Use auto-escaping templates (Jinja2)
# Templates automatically escape {{ user_input }}

# Secure Option 2: Sanitize HTML explicitly
import bleach

ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'a']
ALLOWED_ATTRS = {'a': ['href', 'title']}

clean_html = bleach.clean(
    user_input,
    tags=ALLOWED_TAGS,
    attributes=ALLOWED_ATTRS,
    strip=True
)""",
            "explanation": "Use templating engines with auto-escaping enabled. If you must allow HTML, sanitize it with a library like bleach.",
            "asvs_requirements": ["5.3.3", "5.3.10"],
        },
        "javascript": {
            "title": "XSS Prevention (ASVS 5.3.3)",
            "vulnerable": """// Vulnerable: dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{__html: userInput}} />""",
            "secure": """// Secure: Sanitize with DOMPurify
import DOMPurify from 'dompurify';

const cleanHtml = DOMPurify.sanitize(userInput, {
  ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'a'],
  ALLOWED_ATTR: ['href']
});

<div dangerouslySetInnerHTML={{__html: cleanHtml}} />

// Better: Use React's auto-escaping
<div>{userInput}</div>  // React escapes automatically""",
            "explanation": "React auto-escapes by default. If you must use dangerouslySetInnerHTML, sanitize with DOMPurify first.",
            "asvs_requirements": ["5.3.3", "5.3.10"],
        },
    },
    "weak_password": {
        "python": {
            "title": "Password Validation (ASVS 2.1.1)",
            "vulnerable": """# Vulnerable: Short password allowed
if len(password) < 6:
    raise ValueError("Password too short")""",
            "secure": """# Secure: ASVS-compliant password validation
import re
import pwnedpasswords

def validate_password(password: str) -> bool:
    \"\"\"Validate password against ASVS requirements.\"\"\"
    
    # ASVS 2.1.1: Minimum 12 characters
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    
    # ASVS 2.1.7: Check against breached passwords
    if pwnedpasswords.check(password) > 0:
        raise ValueError("Password has been compromised in a data breach")
    
    # ASVS 2.1.9: No composition rules required
    # (Length is more important than complexity)
    
    return True""",
            "explanation": "Enforce 12+ character minimum and check against breached password databases. Don't require complex composition rules.",
            "asvs_requirements": ["2.1.1", "2.1.7", "2.1.9"],
        },
    },
    "weak_password_hash": {
        "python": {
            "title": "Secure Password Hashing (ASVS 9.2.1)",
            "vulnerable": """# Vulnerable: Weak hashing algorithms
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()
password_hash = hashlib.sha256(password.encode()).hexdigest()""",
            "secure": """# Secure Option 1: Argon2id (recommended)
from passlib.hash import argon2

# Hash password
password_hash = argon2.hash(password)

# Verify password
is_valid = argon2.verify(password, password_hash)

# Secure Option 2: bcrypt
import bcrypt

# Hash password
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Verify password
is_valid = bcrypt.checkpw(password.encode(), password_hash)""",
            "explanation": "Use Argon2id, bcrypt, or scrypt for password hashing. Never use MD5, SHA1, or SHA256 for passwords.",
            "asvs_requirements": ["9.2.1"],
        },
    },
    "hardcoded_secret": {
        "python": {
            "title": "Secure Secret Management (ASVS 2.3.1, 14.3.3)",
            "vulnerable": """# Vulnerable: Hardcoded secrets
API_KEY = "sk-1234567890abcdef"
DATABASE_PASSWORD = "my_secret_password"
SECRET_KEY = "hardcoded_secret_key\"""",
            "secure": """# Secure: Load from environment variables
import os
from dotenv import load_dotenv

load_dotenv()  # Load from .env file (don't commit .env!)

API_KEY = os.environ.get("API_KEY")
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD")
SECRET_KEY = os.environ.get("SECRET_KEY")

# Validate that secrets are loaded
if not API_KEY:
    raise ValueError("API_KEY environment variable not set")

# For production: Use AWS Secrets Manager, Azure Key Vault, etc.
# import boto3
# client = boto3.client('secretsmanager')
# secret = client.get_secret_value(SecretId='my-secret')""",
            "explanation": "Never hardcode secrets in source code. Use environment variables or secret management services.",
            "asvs_requirements": ["2.3.1", "14.3.3"],
        },
    },
    "weak_crypto": {
        "python": {
            "title": "Secure Encryption (ASVS 6.2.2, 6.2.5)",
            "vulnerable": """# Vulnerable: Weak algorithms or ECB mode
from Crypto.Cipher import DES, AES

cipher = DES.new(key, DES.MODE_ECB)  # Weak cipher and mode
cipher = AES.new(key, AES.MODE_ECB)  # Insecure mode""",
            "secure": """# Secure: AES-GCM (authenticated encryption)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Generate key (32 bytes = 256 bits)
key = AESGCM.generate_key(bit_length=256)

# Encrypt
aesgcm = AESGCM(key)
iv = os.urandom(12)  # 96-bit IV for GCM
ciphertext = aesgcm.encrypt(iv, plaintext, None)

# Decrypt
plaintext = aesgcm.decrypt(iv, ciphertext, None)

# High-level API (even easier):
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher = Fernet(key)
ciphertext = cipher.encrypt(plaintext)
plaintext = cipher.decrypt(ciphertext)""",
            "explanation": "Use AES-256 with GCM mode for authenticated encryption. Fernet provides a high-level API with secure defaults.",
            "asvs_requirements": ["6.2.2", "6.2.5", "6.2.6"],
        },
    },
    "session_fixation": {
        "python": {
            "title": "Session Regeneration (ASVS 3.2.1)",
            "vulnerable": """# Vulnerable: No session regeneration on login
@app.route('/login', methods=['POST'])
def login():
    if verify_credentials(username, password):
        session['user_id'] = user_id  # Reuses existing session
        return redirect('/dashboard')""",
            "secure": """# Secure: Regenerate session on login
@app.route('/login', methods=['POST'])
def login():
    if verify_credentials(username, password):
        # Clear old session data
        session.clear()
        
        # Regenerate session ID (Flask does this automatically)
        session.regenerate()  # If available
        
        # Set new session data
        session['user_id'] = user_id
        session['authenticated'] = True
        
        return redirect('/dashboard')""",
            "explanation": "Always regenerate the session ID after successful login to prevent session fixation attacks.",
            "asvs_requirements": ["3.2.1"],
        },
    },
    "missing_secure_flag": {
        "python": {
            "title": "Secure Cookie Configuration (ASVS 3.4.1, 3.4.2, 3.4.5)",
            "vulnerable": """# Vulnerable: Missing security flags
response.set_cookie('session', session_id)""",
            "secure": """# Secure: All security flags set
response.set_cookie(
    'session',
    session_id,
    secure=True,      # ASVS 3.4.1: Only send over HTTPS
    httponly=True,    # ASVS 3.4.2: No JavaScript access
    samesite='Lax',   # ASVS 3.4.5: CSRF protection
    max_age=3600      # 1 hour expiration
)

# Flask configuration approach:
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'""",
            "explanation": "Always set Secure, HttpOnly, and SameSite flags on session cookies for defense-in-depth.",
            "asvs_requirements": ["3.4.1", "3.4.2", "3.4.5"],
        },
    },
    "xxe": {
        "python": {
            "title": "XXE Prevention (ASVS 5.5.2)",
            "vulnerable": """# Vulnerable: Standard XML parser
import xml.etree.ElementTree as ET

tree = ET.parse(xml_file)  # Vulnerable to XXE""",
            "secure": """# Secure: defusedxml library
import defusedxml.ElementTree as ET

# Parse XML safely (XXE protection built-in)
tree = ET.parse(xml_file)

# Or for strings:
root = ET.fromstring(xml_string)

# defusedxml automatically disables:
# - External entity resolution
# - DTD processing
# - Entity expansion""",
            "explanation": "Use defusedxml library which disables dangerous XML features by default. Install with: pip install defusedxml",
            "asvs_requirements": ["5.5.2"],
        },
    },
}


def get_fix_template(vulnerability_type: str, language: str) -> Optional[dict]:
    """
    Get fix template for a vulnerability type and language.

    Args:
        vulnerability_type: Type of vulnerability
        language: Programming language

    Returns:
        Fix template dict or None if not found
    """
    vuln_type = vulnerability_type.lower().replace("-", "_").replace(" ", "_")
    lang = language.lower()

    # Try exact match
    if vuln_type in FIX_TEMPLATES and lang in FIX_TEMPLATES[vuln_type]:
        return FIX_TEMPLATES[vuln_type][lang]

    # Try without language suffix
    for key in FIX_TEMPLATES:
        if key.startswith(vuln_type) or vuln_type.startswith(key):
            if lang in FIX_TEMPLATES[key]:
                return FIX_TEMPLATES[key][lang]

    return None


def get_supported_vulnerability_types() -> list[str]:
    """Get list of vulnerability types with fix templates."""
    return list(FIX_TEMPLATES.keys())


def get_supported_languages(vulnerability_type: str) -> list[str]:
    """Get list of languages supported for a vulnerability type."""
    vuln_type = vulnerability_type.lower().replace("-", "_").replace(" ", "_")
    if vuln_type in FIX_TEMPLATES:
        return list(FIX_TEMPLATES[vuln_type].keys())
    return []

