import os
import yaml

print("🚀 Начинаем обновление проекта...")

# 1. Генерация 45 YAML правил
rules_dir = "rules"
os.makedirs(rules_dir, exist_ok=True)

rules = [
    {"id": "API4-2023-RATE-001", "name": "Unrestricted Resource Consumption", "severity": "medium", "owasp": "API4:2023", "cwe": 770, "description": "Проверка отсутствия ограничения частоты запросов", "conditions": [{"type": "rate_limit", "requests_count": 100, "time_window": 10, "expected_status": 429}], "recommendation": "Внедрить Rate Limiting"},
    {"id": "API8-2023-HEADERS-001", "name": "Missing Security Headers", "severity": "medium", "owasp": "API8:2023", "cwe": 693, "description": "Проверка наличия обязательных заголовков", "conditions": [{"type": "missing_headers", "headers": ["Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"]}], "recommendation": "Настроить заголовки безопасности"},
    {"id": "API8-2023-HTTPS-001", "name": "Missing HTTPS Enforcement", "severity": "high", "owasp": "API8:2023", "cwe": 319, "description": "Проверка принудительного HTTPS", "conditions": [{"type": "https_enforcement", "expected_redirect": True}], "recommendation": "Настроить редирект на HTTPS"},
    {"id": "API2-2023-JWT-ALG-001", "name": "Weak JWT Algorithm", "severity": "high", "owasp": "API2:2023", "cwe": 327, "description": "Проверка уязвимых алгоритмов JWT", "conditions": [{"type": "jwt_algorithm", "test_algorithms": ["none", "HS256"], "expected_status": [401, 403]}], "recommendation": "Использовать RS256/ES256"},
    {"id": "API8-2023-SQLI-001", "name": "SQL Injection", "severity": "critical", "owasp": "API8:2023", "cwe": 89, "description": "Проверка на SQL-инъекции", "conditions": [{"type": "sql_injection", "payloads": ["' OR '1'='1", "'; DROP TABLE--"], "expected_status": [500, 400]}], "recommendation": "Использовать параметризованные запросы"},
    {"id": "API8-2023-XSS-001", "name": "Reflected XSS", "severity": "high", "owasp": "API8:2023", "cwe": 79, "description": "Проверка на XSS", "conditions": [{"type": "xss_reflected", "payloads": ["<script>alert(1)</script>"], "check_response": True}], "recommendation": "Экранировать данные"},
    {"id": "API7-2023-SSRF-001", "name": "SSRF", "severity": "critical", "owasp": "API7:2023", "cwe": 918, "description": "Проверка на SSRF", "conditions": [{"type": "ssrf", "payloads": ["http://127.0.0.1:80", "http://169.254.169.254/"], "expected_status": [400, 403]}], "recommendation": "Валидировать URL"},
    {"id": "API8-2023-TRAVERSAL-001", "name": "Path Traversal", "severity": "high", "owasp": "API8:2023", "cwe": 22, "description": "Проверка на Path Traversal", "conditions": [{"type": "path_traversal", "payloads": ["../../../etc/passwd"], "expected_status": [400, 403]}], "recommendation": "Валидировать пути"},
    {"id": "API8-2023-VERBOSE-001", "name": "Verbose Error Messages", "severity": "low", "owasp": "API8:2023", "cwe": 209, "description": "Раскрытие stack trace", "conditions": [{"type": "verbose_errors", "trigger_payload": "invalid{", "check_patterns": ["Traceback", "Exception"]}], "recommendation": "Скрыть детали ошибок"},
    {"id": "API8-2023-CORS-001", "name": "CORS Misconfiguration", "severity": "high", "owasp": "API8:2023", "cwe": 942, "description": "Слишком разрешительный CORS", "conditions": [{"type": "cors", "origin": "https://evil.com", "check_header": "Access-Control-Allow-Origin"}], "recommendation": "Настроить whitelist CORS"},
    {"id": "API5-2023-NO-AUTH-001", "name": "Missing Authentication", "severity": "critical", "owasp": "API5:2023", "cwe": 306, "description": "Доступ без токена", "conditions": [{"type": "missing_auth", "expected_status": [401, 403]}], "recommendation": "Требовать аутентификацию"},
    {"id": "API1-2023-BOLA-001", "name": "BOLA / IDOR", "severity": "critical", "owasp": "API1:2023", "cwe": 639, "description": "Подмена ID объектов", "conditions": [{"type": "bola", "param_name": "id", "test_values": ["1", "999999"], "expected_status": [403, 404]}], "recommendation": "
