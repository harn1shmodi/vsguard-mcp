# Contributing to ASVS MCP Server

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## How to Contribute

### 1. Report Issues

Found a bug or have a feature request?
- Open an issue on GitHub
- Describe the problem/feature clearly
- Include reproduction steps for bugs
- Mention your environment (OS, Python version)

### 2. Add ASVS Requirements

We're always looking to expand ASVS coverage!

**To add new requirements:**

1. Edit or create YAML file in `data/asvs/`
2. Follow the schema:
   ```yaml
   requirements:
     - id: "X.Y.Z"
       level: 1
       category: "Category Name"
       requirement: "Full requirement text from ASVS"
       cwe: "CWE-XXX"
       description: "Detailed explanation"
       implementation_guide: "How to implement"
       code_examples:
         - "Example code in Python"
         - "Example code in JavaScript"
   ```
3. Test that it loads: `python -c "from src.asvs.loader import get_asvs_collection; print(get_asvs_collection().count())"`
4. Submit a PR

**Priority areas:**
- Access Control (ASVS Chapter 4)
- Error Handling (ASVS Chapter 7)
- Data Protection (ASVS Chapter 8)
- Communications (ASVS Chapter 9)

### 3. Add Semgrep Rules

Create security detection rules!

**To add new rules:**

1. Create or edit YAML file in `data/rules/`
2. Follow Semgrep syntax:
   ```yaml
   rules:
     - id: asvs-X-Y-Z-description
       patterns:
         - pattern: vulnerable_pattern()
       message: |
         ASVS X.Y.Z: Description
         Explanation of vulnerability
         How to fix it
       severity: ERROR
       languages: [python, javascript]
       metadata:
         vulnerability: type_name
         asvs_id: "X.Y.Z"
         cwe: "CWE-XXX"
         remediation: "Fix guidance"
   ```
3. Test locally: `semgrep --config data/rules/your_file.yaml tests/fixtures/vulnerable_code.py`
4. Add test case in `tests/fixtures/`
5. Submit a PR

**Priority vulnerabilities:**
- Path traversal
- SSRF (Server-Side Request Forgery)
- Insecure deserialization
- LDAP injection
- XML injection

### 4. Add Fix Templates

Provide secure code examples!

**To add fix templates:**

1. Edit `src/fixes/templates.py`
2. Add to `FIX_TEMPLATES` dict:
   ```python
   "vulnerability_type": {
       "python": {
           "title": "Descriptive Title (ASVS X.Y.Z)",
           "vulnerable": "# Vulnerable code example",
           "secure": "# Secure code example",
           "explanation": "Why this is better",
           "asvs_requirements": ["X.Y.Z"],
       },
       "javascript": {
           # JS version
       }
   }
   ```
3. Test: Run `pytest tests/test_fix_generator.py`
4. Submit a PR

### 5. Improve Documentation

Documentation improvements are always welcome:
- Fix typos
- Add examples
- Improve explanations
- Add tutorials

### 6. Add Language Support

Expand to more languages!

**Steps:**
1. Update `SUPPORTED_LANGUAGES` in `src/scanners/semgrep_scanner.py`
2. Add language-specific Semgrep rules
3. Add code examples in that language to ASVS YAML files
4. Add fix templates for that language
5. Update README with language support

**High-priority languages:**
- Go
- Rust
- Swift
- Kotlin

## Development Setup

### 1. Fork and Clone

```bash
git clone https://github.com/yourusername/asvs-mcp-server
cd asvs-mcp-server
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
# Development dependencies
pip install -e ".[dev]"

# Or with Poetry
poetry install
```

### 4. Install Pre-commit Hooks (Optional)

```bash
pre-commit install
```

## Coding Standards

### Python Style

- Follow PEP 8
- Use type hints
- Format with Black: `black src/`
- Lint with Ruff: `ruff check src/`
- Type check with mypy: `mypy src/`

### Documentation

- Add docstrings to all public functions
- Use Google-style docstrings:
  ```python
  def function(param: str) -> bool:
      """
      Short description.
      
      Args:
          param: Description
          
      Returns:
          Description
      """
  ```

### Testing

- Write tests for new features
- Maintain >70% coverage
- Run tests: `pytest tests/`
- Run with coverage: `pytest --cov=src tests/`

## Pull Request Process

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### 2. Make Changes

- Write code
- Add tests
- Update documentation
- Ensure tests pass

### 3. Commit

Use clear commit messages:
```bash
git commit -m "Add ASVS 4.1.1 requirement for access control"
git commit -m "Fix SQL injection detection for PostgreSQL"
```

### 4. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub with:
- Clear description of changes
- Why the change is needed
- Any related issues
- Test results

### 5. Code Review

- Respond to feedback
- Make requested changes
- Keep discussion focused and respectful

## Testing Checklist

Before submitting a PR:

- [ ] All tests pass: `pytest tests/`
- [ ] Code formatted: `black src/ tests/`
- [ ] No linting errors: `ruff check src/`
- [ ] Type checking passes: `mypy src/`
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (if applicable)

## Questions?

- Open a GitHub issue
- Tag it as "question"
- We'll respond as soon as possible

## Code of Conduct

### Our Standards

- Be respectful and inclusive
- Welcome newcomers
- Focus on constructive feedback
- Assume good intentions

### Unacceptable Behavior

- Harassment or discriminatory language
- Trolling or insulting comments
- Personal attacks
- Publishing private information

## Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Credited in documentation

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to making AI-assisted development more secure! 🔒🤖

