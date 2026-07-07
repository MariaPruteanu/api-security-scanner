import pytest
import httpx
from unittest.mock import AsyncMock, Mock, patch
from scanner.detectors import APIDetectors

class TestAPIDetectors:
    """Тесты для детекторов уязвимостей"""
    
    @pytest.mark.asyncio
    async def test_missing_headers_detection(self):
        """Тест обнаружения отсутствующих заголовков"""
        detector = APIDetectors("http://test.com")
        
        # Мок ответа без заголовков безопасности
        mock_response = Mock()
        mock_response.headers = {}
        
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        
        rule = {
            "id": "TEST-001",
            "name": "Missing Headers",
            "severity": "medium",
            "owasp": "API8:2023",
            "cwe": 693,
            "recommendation": "Add headers"
        }
        
        condition = {
            "type": "missing_headers",
            "headers": ["Strict-Transport-Security", "X-Frame-Options"]
        }
        
        result = await detector._execute_condition(mock_client, [], rule, condition)
        
        assert result is not None
        assert "Отсутствуют заголовки" in result["evidence"]
    
    @pytest.mark.asyncio
    async def test_sql_injection_detection(self):
        """Тест обнаружения SQL-инъекций"""
        detector = APIDetectors("http://test.com")
        
        # Мок ответа с SQL-ошибкой
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "sqlite3.OperationalError: near \"'\": syntax error"
        
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.post = AsyncMock(return_value=mock_response)
        
        rule = {
            "id": "TEST-002",
            "name": "SQL Injection",
            "severity": "critical",
            "owasp": "API8:2023",
            "cwe": 89,
            "recommendation": "Use parameterized queries"
        }
        
        condition = {
            "type": "sql_injection",
            "payloads": ["' OR '1'='1"],
            "expected_status": [500]
        }
        
        result = await detector._execute_condition(
            mock_client, ["/users"], rule, condition
        )
        
        assert result is not None
        assert "SQL-инъекция" in result["evidence"]
    
    @pytest.mark.asyncio
    async def test_no_vulnerability_detected(self):
        """Тест когда уязвимость не обнаружена"""
        detector = APIDetectors("http://test.com")
        
        # Мок ответа с заголовками безопасности
        mock_response = Mock()
        mock_response.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY"
        }
        
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        
        rule = {
            "id": "TEST-003",
            "name": "Missing Headers",
            "severity": "medium",
            "owasp": "API8:2023",
            "cwe": 693,
            "recommendation": "Add headers"
        }
        
        condition = {
            "type": "missing_headers",
            "headers": ["Strict-Transport-Security", "X-Frame-Options"]
        }
        
        result = await detector._execute_condition(mock_client, [], rule, condition)
        
        # Уязвимость не должна быть обнаружена
        assert result is None
