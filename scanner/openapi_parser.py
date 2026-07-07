import httpx
from typing import List, Dict

class OpenAPIParser:
    """Парсер OpenAPI/Swagger спецификаций"""
    
    def __init__(self, base_url: str, timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.spec = None
    
    async def fetch_spec(self) -> Dict:
        """Получить OpenAPI спецификацию"""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            # Пробуем разные пути к спецификации
            paths = ["/openapi.json", "/swagger.json", "/api/openapi.json", "/v1/openapi.json"]
            
            for path in paths:
                try:
                    resp = await client.get(f"{self.base_url}{path}")
                    if resp.status_code == 200:
                        self.spec = resp.json()
                        print(f"✅ OpenAPI спецификация загружена из {path}")
                        return self.spec
                except Exception as e:
                    continue
            
            print("⚠️ OpenAPI спецификация не найдена, используем базовые эндпоинты")
            return {}
    
    def extract_endpoints(self) -> List[str]:
        """Извлечь список эндпоинтов из спецификации"""
        if not self.spec or "paths" not in self.spec:
            # Базовые эндпоинты, если спецификации нет
            return ["/users/1", "/users/me", "/posts/1", "/products/1", "/login"]
        
        endpoints = []
        for path in self.spec["paths"].keys():
            endpoints.append(path)
        
        print(f"✅ Извлечено эндпоинтов: {len(endpoints)}")
        return endpoints
