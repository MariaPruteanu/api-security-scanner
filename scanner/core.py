import asyncio
import aiohttp
import json
import os
from typing import List, Dict, Any, Optional
from .rules_loader import RulesLoader
from loader import load_specification

class APIScanner:
    def __init__(self, base_url: str, timeout: int = 30, scan_type: str = "basic"):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.scan_type = scan_type
        self.rules_loader = RulesLoader()
        self.rules = self.rules_loader.get_rules_by_tier(scan_type)
        self.session = None
        self.results = []
        self.spec = None

    async def run_scan(self) -> List[Dict[str, Any]]:
        print(f"🔍 Начало сканирования: {self.base_url}")
        self.spec = await self._fetch_openapi()
        if not self.spec:
            print("⚠️ OpenAPI спецификация не найдена, используем базовые эндпоинты")
            endpoints = self._guess_endpoints()
        else:
            endpoints = self._extract_endpoints(self.spec)
        
        print(f"🔍 Найдено эндпоинтов: {len(endpoints)}")
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            self.session = session
            tasks = []
            for endpoint in endpoints:
                for rule in self.rules:
                    tasks.append(self._apply_rule(endpoint, rule))
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, dict) and res.get('vulnerability'):
                    # избегаем дубликатов
                    if not any(r.get('endpoint') == res.get('endpoint') and 
                               r.get('vulnerability') == res.get('vulnerability')
                               for r in self.results):
                        self.results.append(res)
        print(f"✅ Сканирование завершено. Найдено уязвимостей: {len(self.results)}")
        return self.results

    async def _fetch_openapi(self) -> Optional[Dict]:
        try:
            loop = asyncio.get_event_loop()
            spec = await loop.run_in_executor(None, load_specification, self.base_url)
            print(f"📄 Загружена спецификация, версия: {spec.get('openapi', spec.get('swagger', 'unknown'))}")
            return spec
        except Exception as e:
            print(f"⚠️ Ошибка загрузки спецификации: {e}")
            return None

    def _extract_endpoints(self, openapi: Dict) -> List[Dict]:
        endpoints = []
        if 'paths' not in openapi:
            return []
        for path, path_item in openapi['paths'].items():
            for method, operation in path_item.items():
                if method.lower() not in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
                    continue
                all_params = operation.get('parameters', []) + path_item.get('parameters', [])
                security = operation.get('security') or openapi.get('security', [])
                endpoints.append({
                    'path': path,
                    'method': method.upper(),
                    'parameters': all_params,
                    'security': security,
                    'responses': operation.get('responses', {}),
                    'summary': operation.get('summary', ''),
                    'description': operation.get('description', '')
                })
        return endpoints

    def _guess_endpoints(self) -> List[Dict]:
        return [{'path': '/', 'method': 'GET', 'parameters': [], 'security': []}]

    async def _apply_rule(self, endpoint: Dict, rule: Dict) -> Dict:
        rule_name = rule.get('name', '')
        severity = rule.get('severity', 'LOW')
        description = rule.get('description', '')
        recommendation = rule.get('recommendation', '')
        condition = rule.get('condition', {})

        # Проверяем условия правила
        if not self._matches_condition(endpoint, condition):
            return {}

        # Определяем, есть ли уязвимость
        vulnerability = None
        if rule_name.lower().find('https') != -1:
            if not self.base_url.startswith('https'):
                vulnerability = f"API использует HTTP вместо HTTPS (эндпоинт: {endpoint['method']} {endpoint['path']})"
        elif rule_name.lower().find('auth') != -1 or rule_name.lower().find('bol') != -1:
            if not endpoint.get('security'):
                vulnerability = f"Отсутствует аутентификация/авторизация на {endpoint['method']} {endpoint['path']}"
        elif rule_name.lower().find('чувствительных') != -1:
            for param in endpoint.get('parameters', []):
                pname = param.get('name', '').lower()
                if pname in ['password', 'token', 'apikey', 'secret'] and param.get('in') in ['query', 'path']:
                    vulnerability = f"Чувствительный параметр '{pname}' передаётся в {param.get('in')} на {endpoint['method']} {endpoint['path']}"
                    break
        elif rule_name.lower().find('method') != -1:
            if endpoint['method'] in ['OPTIONS', 'TRACE']:
                vulnerability = f"Небезопасный метод {endpoint['method']} разрешён на {endpoint['path']}"
        elif rule_name.lower().find('jwt') != -1:
            # Проверяем, используется ли JWT (по наличию security с type: http, scheme: bearer)
            sec = endpoint.get('security', [])
            if sec:
                for item in sec:
                    for scheme, _ in item.items():
                        if 'bearer' in scheme.lower():
                            # Есть JWT, но возможно слабый алгоритм – пока пропускаем
                            pass
            else:
                vulnerability = f"JWT не используется на {endpoint['method']} {endpoint['path']}"
        elif rule_name.lower().find('rate') != -1:
            # Проверка на rate limiting – в спецификации обычно нет, пропускаем
            pass
        # Добавьте свои проверки здесь

        if vulnerability:
            return {
                'vulnerability': rule_name,
                'severity': severity,
                'description': vulnerability,
                'endpoint': f"{endpoint['method']} {endpoint['path']}",
                'recommendation': recommendation
            }
        return {}

    def _matches_condition(self, endpoint: Dict, condition: Dict) -> bool:
        """Проверяет, соответствует ли эндпоинт условиям правила."""
        # Пример: если условие требует метод GET
        if condition.get('method') and endpoint['method'].lower() != condition['method'].lower():
            return False
        # Если условие требует наличия security
        if condition.get('has_security') is True and not endpoint.get('security'):
            return False
        if condition.get('has_security') is False and endpoint.get('security'):
            return False
        # Если условие требует наличия параметра
        if condition.get('param_name'):
            param_names = [p.get('name', '').lower() for p in endpoint.get('parameters', [])]
            if condition['param_name'].lower() not in param_names:
                return False
        return True
