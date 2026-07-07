import pytest
from scanner.openapi_parser import OpenAPIParser

class TestOpenAPIParser:
    """Тесты для парсера OpenAPI"""
    
    @pytest.mark.asyncio
    async def test_extract_endpoints_from_spec(self):
        """Тест извлечения эндпоинтов из спецификации"""
        parser = OpenAPIParser("http://test.com")
        
        # Имитируем загруженную спецификацию
        parser.spec = {
            "paths": {
                "/users": {"get": {}, "post": {}},
                "/users/{id}": {"get": {}, "put": {}, "delete": {}},
                "/login": {"post": {}}
            }
        }
        
        endpoints = parser.extract_endpoints()
        
        assert len(endpoints) == 3
        assert "/users" in endpoints
        assert "/users/{id}" in endpoints
        assert "/login" in endpoints
    
    @pytest.mark.asyncio
    async def test_extract_endpoints_without_spec(self):
        """Тест извлечения эндпоинтов без спецификации"""
        parser = OpenAPIParser("http://test.com")
        parser.spec = None
        
        endpoints = parser.extract_endpoints()
        
        # Должны вернуться базовые эндпоинты
        assert len(endpoints) > 0
        assert "/users/1" in endpoints or "/users/me" in endpoints
    
    @pytest.mark.asyncio
    async def test_extract_endpoints_empty_paths(self):
        """Тест извлечения эндпоинтов из пустой спецификации"""
        parser = OpenAPIParser("http://test.com")
        parser.spec = {"paths": {}}
        
        endpoints = parser.extract_endpoints()
        
        assert len(endpoints) == 0
