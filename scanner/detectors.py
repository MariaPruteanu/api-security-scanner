"""
Модуль детекторов уязвимостей API
Реализация проверок OWASP API Security Top 10 (2023)
ВКР МИФИ 2026 - Прутеану Мария
"""

import httpx
from typing import List, Dict, Optional


class APIDetectors:
    """Класс детекторов уязвимостей API"""
    
    def __init__(self, base_url: str, timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
    
    async def detect_bola(
        self, 
        client: httpx.AsyncClient, 
        endpoint: str
    ) -> Optional[Dict]:
        """
        Детектор BOLA (API1:2023) - Broken Object Level Authorization
        
        Метод: Подмена идентификатора объекта в запросе
        Пример: GET /users/1 → GET /users/999999
        
        :param client: HTTP клиент
        :param endpoint: Эндпоинт для проверки
        :return: Словарь с информацией об уязвимости или None
        """
        try:
            # Запрос с оригинальным ID
            original_resp = await client.get(
                f"{self.base_url}{endpoint.replace('{id}', '1')}"
            )
            
            if original_resp.status_code != 200:
                return None
            
            # Запрос с подменённым ID
            test_resp = await client.get(
                f"{self.base_url}{endpoint.replace('{id}', '999999')}"
            )
            
            # Если доступ разрешён к чужому объекту - уязвимость
            if test_resp.status_code == 200:
                if original_resp.json() != test_resp.json():
                    return {
                        "vulnerability": "BOLA (API1:2023)",
                        "severity": "CRITICAL",
                        "endpoint": endpoint,
                        "evidence": "Доступ к чужому объекту разрешён (ID=999999)",
                        "owasp": "API1:2023",
                        "cwe": "CWE-639",
                        "recommendation": "Реализовать проверку прав доступа на уровне объектов"
                    }
        except Exception as e:
            pass
        
        return None
    
    async def detect_mass_assignment(
        self, 
        client: httpx.AsyncClient, 
        endpoint: str
    ) -> Optional[Dict]:
        """
        Детектор Mass Assignment (API6:2023)
        
        Метод: Попытка присвоения привилегированных полей
        Пример: PATCH /users/1 {"isAdmin": true}
        
        :param client: HTTP клиент
        :param endpoint: Эндпоинт для проверки
        :return: Словарь с информацией об уязвимости или None
        """
        try:
            # Попытка изменить привилегированные поля
            test_payload = {
                "isAdmin": True,
                "role": "admin",
                "privileges": "full"
            }
            
            resp = await client.patch(
                f"{self.base_url}{endpoint}",
                json=test_payload
            )
            
            if resp.status_code == 200:
                data = resp.json()
                # Если поля были приняты - уязвимость
                if data.get("isAdmin") or data.get("role") == "admin":
                    return {
                        "vulnerability": "Mass Assignment (API6:2023)",
                        "severity": "HIGH",
                        "endpoint": endpoint,
                        "evidence": "Возможно присвоение привилегированных полей",
                        "owasp": "API6:2023",
                        "cwe": "CWE-915",
                        "recommendation": "Использовать whitelist полей для обновления"
                    }
        except Exception as e:
            pass
        
        return None
    
    async def detect_excessive_data(
        self, 
        client: httpx.AsyncClient, 
        endpoint: str
    ) -> Optional[Dict]:
        """
        Детектор Excessive Data Exposure (API3:2023)
        
        Метод: Анализ возвращаемых данных на чувствительные поля
        Пример: GET /users/1 возвращает password, email, phone
        
        :param client: HTTP клиент
        :param endpoint: Эндпоинт для проверки
        :return: Словарь с информацией об уязвимости или None
        """
        try:
            resp = await client.get(f"{self.base_url}{endpoint}")
            
            if resp.status_code == 200:
                data = resp.json()
                
                # Список чувствительных полей
                sensitive_fields = [
                    "password", "email", "phone", "address", 
                    "token", "secret", "ssn", "credit_card"
                ]
                
                # Поиск чувствительных данных в ответе
                found_fields = [
                    f for f in sensitive_fields 
                    if f in str(data).lower()
                ]
                
                if found_fields:
                    return {
                        "vulnerability": "Excessive Data Exposure (API3:2023)",
                        "severity": "MEDIUM",
                        "endpoint": endpoint,
                        "evidence": f"Раскрыты чувствительные поля: {', '.join(found_fields)}",
                        "owasp": "API3:2023",
                        "cwe": "CWE-200",
                        "recommendation": "Возвращать только необходимые поля для текущей роли"
                    }
        except Exception as e:
            pass
        
        return None
    
    async def detect_broken_auth(
        self, 
        client: httpx.AsyncClient, 
        endpoint: str
    ) -> Optional[Dict]:
        """
        Детектор Broken Authentication (API2:2023)
        
        Метод: Тестирование с невалидными токенами
        Пример: GET /users/me с токеном "invalid_token"
        
        :param client: HTTP клиент
        :param endpoint: Эндпоинт для проверки
        :return: Словарь с информацией об уязвимости или None
        """
        try:
            # Запрос с невалидным токеном
            resp = await client.get(
                f"{self.base_url}{endpoint}",
                headers={"Authorization": "Bearer invalid_token_12345"}
            )
            
            # Если доступ разрешён - уязвимость
            if resp.status_code == 200:
                return {
                    "vulnerability": "Broken Authentication (API2:2023)",
                    "severity": "HIGH",
                    "endpoint": endpoint,
                    "evidence": "Доступ разрешён с невалидным JWT токеном",
                    "owasp": "API2:2023",
                    "cwe": "CWE-306",
                    "recommendation": "Реализовать правильную валидацию JWT токенов"
                }
        except Exception as e:
            pass
        
        return None
    
    async def run_all_detectors(
        self, 
        client: httpx.AsyncClient, 
        endpoints: List[str]
    ) -> List[Dict]:
        """
        Запуск всех детекторов на списке эндпоинтов
        
        :param client: HTTP клиент
        :param endpoints: Список эндпоинтов для проверки
        :return: Список найденных уязвимостей
        """
        findings = []
        
        for endpoint in endpoints:
            # BOLA
            result = await self.detect_bola(client, endpoint)
            if result:
                findings.append(result)
            
            # Mass Assignment
            result = await self.detect_mass_assignment(client, endpoint)
            if result:
                findings.append(result)
            
            # Excessive Data Exposure
            result = await self.detect_excessive_data(client, endpoint)
            if result:
                findings.append(result)
            
            # Broken Authentication
            result = await self.detect_broken_auth(client, endpoint)
            if result:
                findings.append(result)
        
        return findings
