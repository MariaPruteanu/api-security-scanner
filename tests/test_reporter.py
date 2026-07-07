import pytest
import os
from scanner.reporter import HTMLReporter

class TestHTMLReporter:
    """Тесты для генератора HTML-отчётов"""
    
    def test_reporter_initialization(self):
        """Тест инициализации репортера"""
        findings = [
            {
                "vulnerability": "SQL Injection",
                "severity": "CRITICAL",
                "endpoint": "/users",
                "evidence": "SQL error detected",
                "owasp": "API8:2023",
                "cwe": "CWE-89",
                "recommendation": "Use parameterized queries"
            }
        ]
        
        reporter = HTMLReporter(findings, "http://test.com", "test_user")
        
        assert reporter.target_url == "http://test.com"
        assert reporter.scanned_by == "test_user"
        assert len(reporter.findings) == 1
        assert reporter.critical == 1
        assert reporter.high == 0
        assert reporter.medium == 0
    
    def test_report_generation(self, tmp_path):
        """Тест генерации HTML-отчёта"""
        findings = [
            {
                "vulnerability": "XSS",
                "severity": "HIGH",
                "endpoint": "/search",
                "evidence": "Reflected XSS",
                "owasp": "API8:2023",
                "cwe": "CWE-79",
                "recommendation": "Escape output"
            },
            {
                "vulnerability": "Missing Headers",
                "severity": "MEDIUM",
                "endpoint": "N/A",
                "evidence": "Missing X-Frame-Options",
                "owasp": "API8:2023",
                "cwe": "CWE-693",
                "recommendation": "Add security headers"
            }
        ]
        
        reporter = HTMLReporter(findings, "http://test.com", "test_user")
        
        # Генерируем отчёт
        report_path = tmp_path / "test_report.html"
        reporter.save(str(report_path))
        
        # Проверяем, что файл создан
        assert os.path.exists(report_path)
        
        # Проверяем содержимое
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
            assert "XSS" in content
            assert "Missing Headers" in content
            assert "http://test.com" in content
            assert "test_user" in content
    
    def test_severity_counting(self):
        """Тест подсчёта уязвимостей по критичности"""
        findings = [
            {"severity": "CRITICAL", "vulnerability": "Test 1"},
            {"severity": "CRITICAL", "vulnerability": "Test 2"},
            {"severity": "HIGH", "vulnerability": "Test 3"},
            {"severity": "MEDIUM", "vulnerability": "Test 4"},
            {"severity": "MEDIUM", "vulnerability": "Test 5"},
            {"severity": "LOW", "vulnerability": "Test 6"}
        ]
        
        reporter = HTMLReporter(findings, "http://test.com", "test_user")
        
        assert reporter.critical == 2
        assert reporter.high == 1
        assert reporter.medium == 2
