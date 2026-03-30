import asyncio
import httpx
from typing import List, Dict
from datetime import datetime

class APIScanner:
    def __init__(self, base_url: str, timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.findings = []
    
    async def check_bola(self, client: httpx.AsyncClient) -> List[Dict]:
        findings = []
        test_endpoints = ["/users/1", "/posts/1", "/products/1"]
        for endpoint in test_endpoints:
            try:
                resp1 = await client.get(f"{self.base_url}{endpoint}")
                resp2 = await client.get(f"{self.base_url}{endpoint.replace('1', '999999')}")
                if resp1.status_code == 200 and resp2.status_code == 200:
                    if resp1.json() != resp2.json():
                        findings.append({
                            "vulnerability": "BOLA (API1:2023)",
                            "severity": "CRITICAL",
                            "endpoint": endpoint,
                            "evidence": f"Доступ к объекту {endpoint.replace('1', '999999')} разрешён",
                            "owasp": "API1:2023",
                            "cwe": "CWE-639",
                            "recommendation": "Реализовать проверку прав доступа на уровне объектов"
                        })
            except:
                pass
        return findings
    
    async def check_mass_assignment(self, client: httpx.AsyncClient) -> List[Dict]:
        findings = []
        try:
            resp = await client.patch(f"{self.base_url}/users/1",
                                      json={"isAdmin": True, "role": "admin"})
            if resp.status_code == 200:
                data = resp.json()
                if data.get("isAdmin") or data.get("role") == "admin":
                    findings.append({
                        "vulnerability": "Mass Assignment (API6:2023)",
                        "severity": "HIGH",
                        "endpoint": "/users/1",
                        "evidence": "Возможно присвоение привилегированных полей",
                        "owasp": "API6:2023",
                        "cwe": "CWE-915",
                        "recommendation": "Использовать whitelist полей для обновления"
                    })
        except:
            pass
        return findings
    
    async def check_excessive_data(self, client: httpx.AsyncClient) -> List[Dict]:
        findings = []
        try:
            resp = await client.get(f"{self.base_url}/users/1")
            if resp.status_code == 200:
                data = resp.json()
                sensitive_fields = ["password", "email", "phone", "address", "token", "secret"]
                found_fields = [f for f in sensitive_fields if f in str(data).lower()]
                if found_fields:
                    findings.append({
                        "vulnerability": "Excessive Data Exposure (API3:2023)",
                        "severity": "MEDIUM",
                        "endpoint": "/users/1",
                        "evidence": f"Раскрыты чувствительные поля: {', '.join(found_fields)}",
                        "owasp": "API3:2023",
                        "cwe": "CWE-200",
                        "recommendation": "Возвращать только необходимые поля для текущей роли"
                    })
        except:
            pass
        return findings
    
    async def check_broken_auth(self, client: httpx.AsyncClient) -> List[Dict]:
        findings = []
        try:
            resp = await client.get(f"{self.base_url}/users/me",
                                   headers={"Authorization": "Bearer invalid_token_12345"})
            if resp.status_code == 200:
                findings.append({
                    "vulnerability": "Broken Authentication (API2:2023)",
                    "severity": "HIGH",
                    "endpoint": "/users/me",
                    "evidence": "Доступ разрешён с невалидным JWT токеном",
                    "owasp": "API2:2023",
                    "cwe": "CWE-306",
                    "recommendation": "Реализовать правильную валидацию JWT токенов"
                })
        except:
            pass
        return findings
    
    async def run_scan(self) -> List[Dict]:
        print(f"\n🔍 Начало сканирования: {self.base_url}")
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            results = await asyncio.gather(
                self.check_bola(client),
                self.check_mass_assignment(client),
                self.check_excessive_data(client),
                self.check_broken_auth(client),
                return_exceptions=True
            )
        for result in results:
            if isinstance(result, list):
                self.findings.extend(result)
        print(f"✅ Сканирование завершено. Найдено уязвимостей: {len(self.findings)}")
        return self.findings
