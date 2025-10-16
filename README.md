# VSGuard MCP

A production-ready Model Context Protocol (MCP) server that provides real-time OWASP ASVS security guidance and vulnerability scanning for AI coding agents.

## Overview

This MCP server integrates with Claude Desktop, Cursor, and other MCP-compatible tools to enable **proactive security during code generation**. It helps AI agents write secure code from the start by providing:

- **OWASP ASVS Requirements** - Real-time security guidance based on ASVS v4.0
- **Vulnerability Scanning** - Static analysis using Semgrep with custom ASVS rules
- **Secure Code Fixes** - Actionable remediation with code examples
- **LLM-Optimized Output** - Formatted for maximum comprehension by AI agents

## Features

### Three Core Tools

1. **`check_security_requirements`** - Get relevant ASVS requirements before writing code
2. **`scan_code`** - Analyze code for vulnerabilities with ASVS mappings
3. **`suggest_fix`** - Generate secure code alternatives with explanations

### Security Coverage

- ✅ Authentication (ASVS Chapter 2)
- ✅ Session Management (ASVS Chapter 3)
- ✅ Access Control (ASVS Chapter 4)
- ✅ Input Validation & Injection Prevention (ASVS Chapter 5)
- ✅ Cryptography (ASVS Chapters 6-9)
- ✅ Data Protection

### Supported Languages

- Python (primary)
- JavaScript/TypeScript
- Java, Go, Ruby, PHP, C/C++, C#, Rust (via Semgrep)

## Quick Start

### Prerequisites

- Python 3.11+
- pip or Poetry
- Semgrep (for scanning)

### Installation

```bash
# Clone repository
git clone https://github.com/yourname/vsguard-mcp
cd vsguard-mcp

# Install dependencies
pip install -e .

# Or with Poetry
poetry install
```

### Running the Server

```bash
# Run directly with FastMCP
python src/server.py
```

### Configure Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vsguard": {
      "command": "python",
      "args": ["/absolute/path/to/vsguard-mcp/src/server.py"]
    }
  }
}
```

Restart Claude Desktop to load the server.

## Usage Examples

### Example 1: Get Security Requirements during code generation

**In Claude Desktop:**
```
Create a user login endpoint, follow asvs requirements.
```

**Claude will call:**
```python
check_security_requirements(
    code_type="authentication",
    language="python"
)
```

**Response:**
```markdown
# OWASP ASVS Security Requirements

## Level 1 Requirements (8)

### 2.1.1: Password Security
Requirement: Verify that user set passwords are at least 12 characters in length.

Implementation Guide:
- Add validation during user registration and password change
- Reject passwords shorter than 12 characters
- Consider allowing longer passwords (64+ chars)

Code Example:
```python
def validate_password_length(password: str) -> bool:
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    return True
```

### Example 2: Scan Existing Code for Vulnerabilities

**In Claude Desktop:**
```
Can you check the login logic code for security issues?
```

**Claude will call:**
```python
scan_code(
    code="""def login(username, password):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)""",
    language="python"
)
```

**Response:**
```markdown
❌ SCAN FAILED

Total Findings: 1
- 🟠 HIGH: 1

ASVS Requirements Violated: 5.3.4, 5.3.5

## Detailed Findings

### 1. 🟠 SQL Injection
Severity: HIGH
ASVS Requirements: 5.3.4, 5.3.5

Issue:
SQL injection vulnerability detected. User input is concatenated directly into SQL query.

Location: input.py:line 2

Vulnerable Code:
query = f"SELECT * FROM users WHERE username = '{username}'"

Remediation:
Use parameterized queries with placeholders instead of string concatenation.

Example:
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```

### Example 3: Get Secure Code Fix

**In Claude Desktop:**
```
How do I fix this SQL injection vulnerability?
```

**Claude will call:**
```python
suggest_fix(
    vulnerable_code="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
    vulnerability_type="sql_injection",
    language="python"
)
```

**Response:**
```markdown
# Security Fix Suggestion

ASVS Requirements Addressed 5.3.4, 5.3.5

## ❌ Vulnerable Code
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

## ✅ Secure Code
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Or with SQLAlchemy ORM:
from sqlalchemy import select
stmt = select(User).where(User.username == username)
user = session.execute(stmt).scalar_one_or_none()
```


## Configuration

Create a `.env` file (optional):

```env
# ASVS settings
MIN_ASVS_LEVEL=1

# Scanner settings
ENABLE_SEMGREP=true
SCAN_TIMEOUT=30
MAX_CODE_SIZE=50000

# Logging
LOG_LEVEL=INFO
```

## Testing

```bash
# Run tests
pytest tests/

# Run specific test
pytest tests/test_asvs_loader.py

# With coverage
pytest --cov=src tests/
```

## Coverage

Current implementation includes:

- **40+ ASVS Requirements** across authentication, session management, input validation, and cryptography
- **25+ Custom Semgrep Rules** detecting common vulnerabilities
- **10+ Fix Templates** with secure code examples
- **Multiple Languages** supported (Python, JavaScript, TypeScript, etc.)

### Vulnerability Detection

- SQL Injection (ASVS 5.3.4, 5.3.5)
- Cross-Site Scripting (ASVS 5.3.3, 5.3.10)
- Weak Password Validation (ASVS 2.1.1, 2.1.7)
- Weak Cryptography (ASVS 6.2.2, 6.2.5)
- Hardcoded Secrets (ASVS 2.3.1, 14.3.3)
- Session Management Issues (ASVS 3.x)
- XML External Entity (XXE) (ASVS 5.5.2)
- Command Injection (ASVS 5.3.4)
- And more...

## How It Works

### 1. ASVS Requirements Database

The server loads OWASP ASVS v4.0 requirements from structured YAML files:

```yaml
requirements:
  - id: "2.1.1"
    level: 1
    category: "Password Security"
    requirement: "Verify that user set passwords are at least 12 characters in length."
    cwe: "CWE-521"
    description: "Passwords should be sufficiently long..."
    implementation_guide: "Add validation during registration..."
    code_examples:
      - |
        if len(password) < 12:
            raise ValueError("Too short")
```

### 2. Static Analysis with Semgrep

Custom Semgrep rules detect ASVS violations:

```yaml
rules:
  - id: asvs-5-3-4-sql-injection
    pattern: cursor.execute(f"... {$VAR} ...")
    message: "ASVS 5.3.4: SQL injection vulnerability"
    severity: ERROR
    metadata:
      asvs_id: "5.3.4"
      cwe: "CWE-89"
```

### 3. Intelligent Mapping

Findings are automatically mapped to ASVS requirements by:
- Vulnerability type (sql_injection → ASVS 5.3.4)
- CWE ID (CWE-89 → ASVS 5.3.4, 5.3.5)
- Code patterns (login endpoints → authentication requirements)

### 4. LLM-Optimized Output

All responses are formatted for maximum LLM comprehension:
- Clear structure with headers and sections
- Code examples with syntax highlighting
- Severity indicators (🔴 🟠 🟡)
- Actionable remediation steps
- ASVS requirement references

## 🔧 Extending the Server

### Add New ASVS Requirements

Create/edit YAML files in `data/asvs/`:

```yaml
requirements:
  - id: "X.Y.Z"
    level: 1
    category: "Your Category"
    requirement: "Requirement text"
    cwe: "CWE-XXX"
    description: "Detailed explanation"
    implementation_guide: "How to implement"
    code_examples:
      - "Example code"
```

### Add Custom Semgrep Rules

Create YAML files in `data/rules/`:

```yaml
rules:
  - id: custom-rule-id
    patterns:
      - pattern: vulnerable_pattern()
    message: "Vulnerability description"
    severity: ERROR
    metadata:
      asvs_id: "X.Y.Z"
      cwe: "CWE-XXX"
      remediation: "How to fix"
```

### Add Fix Templates

Edit `src/fixes/templates.py`:

```python
FIX_TEMPLATES = {
    "vulnerability_type": {
        "python": {
            "vulnerable": "# Bad code",
            "secure": "# Good code",
            "explanation": "Why it's better",
            "asvs_requirements": ["X.Y.Z"],
        }
    }
}
```

## 🤝 Contributing

Contributions welcome! Areas for improvement:

1. **More ASVS Requirements** - Cover additional chapters
2. **More Languages** - Expand language support
3. **More Scanners** - Integrate Bandit, detect-secrets
4. **Better AI Integration** - Improve LLM output formatting
5. **Performance** - Optimize scanning speed

## ⚡ Powered By

- **FastMCP 2.0** - Modern Python framework for MCP servers
- **Semgrep** - Static analysis engine
- **OWASP ASVS** - Security verification standard

## 📝 License

MIT License - see LICENSE file for details.

## 🔗 Resources

- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [Semgrep](https://semgrep.dev/)
- [Claude Desktop](https://claude.ai/download)

## 🙏 Acknowledgments

- OWASP for the ASVS standard
- Anthropic for the MCP protocol
- Semgrep for the scanning engine

## 📧 Support

For issues, questions, or contributions, please open an issue on GitHub.

---

**Built with ❤️ for secure AI-assisted development**

