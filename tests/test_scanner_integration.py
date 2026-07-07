import pytest
from scanner.core import APIScanner

class TestAPIScannerIntegration:
    """Интеграционные тесты для сканера"""
    
    @pytest.mark.asyncio
    async def test_scanner_initialization(self):
        """Тест инициализации сканера"""
        scanner = APIScanner("http://test.com")
        
        assert scanner.base_url == "http://test.com"
        assert scanner.timeout == 15.0
        assert len(scanner.findings) == 0
    
    @pytest.mark.asyncio
    async def test_scanner_with_mock_target(self):
        """Тест сканирования с мок-целью"""
        # Этот тест требует запущенного тестового API
        # Пока пропускаем, но можно добавить в будущем
        pytest.skip("Requires running test API")
