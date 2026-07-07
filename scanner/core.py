import asyncio
import httpx
from typing import List, Dict
from datetime import datetime
from .openapi_parser import OpenAPIParser
from .detectors import APIDetectors

class APIScanner:
    def __init__(self, base_url: str, timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.findings = []
        self.parser = OpenAPIParser(base_url, timeout)
        self.detectors = APIDetectors(base_url, timeout)
    
    async def run_scan(self) -> List[Dict]:
        print(f"\n🔍 Начало сканирования: {self.base_url}")
        
        # Получаем спецификацию и эндпоинты
        await self.parser.fetch_spec()
        endpoints = self.parser.extract_endpoints()
        
        # Запускаем проверки через универсальный движок
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            self.findings = await self.detectors.run_all_detectors(client, endpoints)
        
        print(f"✅ Сканирование завершено. Найдено уязвимостей: {len(self.findings)}")
        return self.findings
