import pytest
import tempfile
import os

@pytest.fixture
def temp_directory():
    """Создаёт временную директорию для тестов"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir

@pytest.fixture
def sample_findings():
    """Пример списка уязвимостей для тестов"""
    return [
        {
            "vulnerability": "SQL Injection",
            "severity": "CRITICAL",
            "endpoint": "/users",
            "evidence": "SQL error detected",
            "owasp": "API8:2023",
            "cwe": "CWE-89",
            "recommendation": "Use parameterized queries"
        },
        {
            "vulnerability": "XSS",
            "severity": "HIGH",
            "endpoint": "/search",
            "evidence": "Reflected XSS",
            "owasp": "API8:2023",
            "cwe": "CWE-79",
            "recommendation": "Escape output"
        }
    ]
