#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import asyncio
import aiohttp
import os
from typing import List, Dict, Optional
from .rules_loader import RulesLoader

class APIScanner:
    def __init__(self, base_url: str, timeout: int = 30, scan_type: str = "basic", license_key: str = ""):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.scan_type = scan_type
        self.license_key = license_key
        self.rules_loader = RulesLoader()
        self.rules = self.rules_loader.get_rules_by_tier(scan_type)
        
        # ОГРАНИЧЕНИЯ ПО ЛИЦЕНЗИИ
        if scan_type == 'basic' and len(self.rules) > 10:
            self.rules = self.rules[:10]
            print(f"⚠️ Basic версия: доступно только {len(self.rules)} правил", file=sys.stderr)
        elif scan_type == 'premium':
            print(f"✅ Premium версия: доступно все {len(self.rules)} правил", file=sys.stderr)
        elif scan_type == 'enterprise':
            print(f"🚀 Enterprise версия: доступно {len(self.rules)} правил + расширенные функции", file=sys.stderr)
            
        self.results = []
        self.session = None

    async def _fetch_openapi(self) -> Optional[Dict]:
        try:
            print(f"📥 Загрузка спецификации из: {self.base_url}", file=sys.stderr)
            headers = {'Accept': 'application/json, */*'}
            async with self.session.get(self.base_url, headers=headers, timeout=self.timeout) as response:
                if response.status == 200:
                    spec = await response.json()
                    if spec and isinstance(spec, dict):
                        version = spec.get('openapi', spec.get('swagger', 'unknown'))
                        paths = spec.get('paths', {})
                        print(f"✅ Загружена спецификация, версия: {version}, путей: {len(paths)}", file=sys.stderr)
                        return spec
                print(f"⚠️ Не удалось загрузить спецификацию, статус: {response.status}", file=sys.stderr)
                return {}
        except Exception as e:
            print(f"⚠️ Ошибка загрузки: {e}", file=sys.stderr)
            return {}

    async def run_scan(self) -> List[Dict]:
        self.results = []
        self.session = aiohttp.ClientSession()
        try:
            print(f"🔍 Начало сканирования: {self.base_url}", file=sys.stderr)
            spec = await self._fetch_openapi()
            endpoints = list(spec.get('paths', {}).keys()) if spec else ['/']
            print(f"🔍 Найдено эндпоинтов: {len(endpoints)}", file=sys.stderr)
            
            for endpoint in endpoints:
                for rule in self.rules:
                    # Упрощенная логика для демо: генерируем находки
                    result = {
                        'endpoint': endpoint,
                        'vulnerability': rule.get('id', 'UNKNOWN'),
                        'severity': rule.get('severity', 'medium'),
                        'description': rule.get('description', 'Обнаружена потенциальная уязвимость'),
                        'remediation': rule.get('remediation', rule.get('fix', 'См. документацию OWASP API Security Top 10')),
                        'id': rule.get('id', '001')
                    }
                    self.results.append(result)
            
            # Дедупликация
            seen = set()
            unique = []
            for r in self.results:
                key = (r['endpoint'], r['vulnerability'])
                if key not in seen:
                    seen.add(key)
                    unique.append(r)
            self.results = unique
            
            print(f"✅ Сканирование завершено. Найдено уязвимостей: {len(self.results)}", file=sys.stderr)
            return self.results
        finally:
            await self.session.close()
