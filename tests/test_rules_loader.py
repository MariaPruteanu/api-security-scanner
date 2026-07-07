import pytest
import os
import yaml
from scanner.rules_loader import RulesLoader

class TestRulesLoader:
    """Тесты для загрузчика YAML-правил"""
    
    def test_load_rules_from_directory(self, tmp_path):
        """Тест загрузки правил из директории"""
        # Создаём тестовую директорию с правилами
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        
        # Создаём тестовое правило
        test_rule = {
            "id": "TEST-001",
            "name": "Test Rule",
            "severity": "high",
            "owasp": "API8:2023",
            "cwe": 999,
            "description": "Test description",
            "conditions": [{"type": "test", "payload": "test"}],
            "recommendation": "Test recommendation"
        }
        
        rule_file = rules_dir / "test_rule.yaml"
        with open(rule_file, 'w') as f:
            yaml.dump(test_rule, f)
        
        # Загружаем правила
        loader = RulesLoader(str(rules_dir))
        
        assert len(loader.rules) == 1
        assert loader.rules[0]['id'] == "TEST-001"
        assert loader.rules[0]['severity'] == "high"
    
    def test_get_rules_by_type(self, tmp_path):
        """Тест фильтрации правил по типу"""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        
        # Создаём несколько правил с разными типами
        rules = [
            {
                "id": "TEST-001",
                "name": "SQL Injection",
                "severity": "critical",
                "owasp": "API8:2023",
                "cwe": 89,
                "conditions": [{"type": "sql_injection", "payloads": ["' OR 1=1"]}]
            },
            {
                "id": "TEST-002",
                "name": "XSS",
                "severity": "high",
                "owasp": "API8:2023",
                "cwe": 79,
                "conditions": [{"type": "xss_reflected", "payloads": ["<script>"]}]
            }
        ]
        
        for i, rule in enumerate(rules):
            rule_file = rules_dir / f"rule_{i}.yaml"
            with open(rule_file, 'w') as f:
                yaml.dump(rule, f)
        
        loader = RulesLoader(str(rules_dir))
        
        # Проверяем фильтрацию
        sql_rules = loader.get_rules_by_type("sql_injection")
        assert len(sql_rules) == 1
        assert sql_rules[0]['id'] == "TEST-001"
        
        xss_rules = loader.get_rules_by_type("xss_reflected")
        assert len(xss_rules) == 1
        assert xss_rules[0]['id'] == "TEST-002"
    
    def test_empty_directory(self, tmp_path):
        """Тест загрузки из пустой директории"""
        rules_dir = tmp_path / "empty_rules"
        rules_dir.mkdir()
        
        loader = RulesLoader(str(rules_dir))
        assert len(loader.rules) == 0
    
    def test_nonexistent_directory(self):
        """Тест обработки несуществующей директории"""
        loader = RulesLoader("/nonexistent/path")
        assert len(loader.rules) == 0
