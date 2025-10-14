"""Pytest configuration and fixtures."""

import pytest
from pathlib import Path


@pytest.fixture
def project_root():
    """Get project root directory."""
    return Path(__file__).parent.parent


@pytest.fixture
def data_dir(project_root):
    """Get data directory."""
    return project_root / "data"


@pytest.fixture
def asvs_data_dir(data_dir):
    """Get ASVS data directory."""
    return data_dir / "asvs"


@pytest.fixture
def rules_dir(data_dir):
    """Get rules directory."""
    return data_dir / "rules"


@pytest.fixture
def sample_vulnerable_code():
    """Sample vulnerable code for testing."""
    return """
def login(username, password):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()
"""


@pytest.fixture
def sample_secure_code():
    """Sample secure code for testing."""
    return """
def login(username, password):
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()
"""

