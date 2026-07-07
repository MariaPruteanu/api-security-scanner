import httpx
from typing import List, Dict, Optional
from .rules_loader import RulesLoader

class APIDetectors:
    """Класс детекторов уязвимостей API с поддержкой YAML-правил"""

    def __init__(self, base_url: str, timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.rules_loader = RulesLoader()

    async def run_all_detectors(
        self,
        client: httpx.AsyncClient,
        endpoints: List[str]
    ) -> List[Dict]:
        """Запуск всех проверок на основе загруженных YAML-правил"""
        findings = []
        
        print(f"🔍 Запуск {len(self.rules_loader.rules)} проверок из YAML...")
        
        for rule in self.rules_loader.rules:
            for condition in rule.get("conditions", []):
                result = await self._execute_condition(client, endpoints, rule, condition)
                if result:
                    findings.append(result)
                    
        return findings

    async def _execute_condition(
        self, 
        client: httpx.AsyncClient, 
        endpoints: List[str], 
        rule: Dict, 
        condition: Dict
    ) -> Optional[Dict]:
        """Универсальный исполнитель условий из YAML"""
        cond_type = condition.get("type")
        
        # Базовая структура найденной уязвимости
        base_result = {
            "vulnerability": f"{rule['name']} ({rule['owasp']})",
            "severity": rule['severity'].upper(),
            "endpoint": "N/A",
            "evidence": "",
            "owasp": rule['owasp'],
            "cwe": f"CWE-{rule['cwe']}",
            "recommendation": rule['recommendation']
        }

        try:
            # --- ПРОВЕРКИ ЗАГОЛОВКОВ И КОНФИГУРАЦИИ ---
            if cond_type == "missing_headers":
                resp = await client.get(f"{self.base_url}/")
                missing = [h for h in condition.get("headers", []) if h not in resp.headers]
                if missing:
                    base_result["evidence"] = f"Отсутствуют заголовки: {', '.join(missing)}"
                    return base_result

            elif cond_type == "hsts" or cond_type == "csp" or cond_type == "clickjacking" or cond_type == "mime_sniffing":
                resp = await client.get(f"{self.base_url}/")
                header = condition.get("check_header")
                if header and header not in resp.headers:
                    base_result["evidence"] = f"Отсутствует заголовок {header}"
                    return base_result
                elif header and "expected_value" in condition:
                    if resp.headers.get(header) != condition["expected_value"]:
                        base_result["evidence"] = f"Заголовок {header} имеет неверное значение"
                        return base_result

            elif cond_type == "info_disclosure":
                resp = await client.get(f"{self.base_url}/")
                found = [h for h in condition.get("headers", []) if h in resp.headers]
                if found:
                    base_result["evidence"] = f"Раскрыты заголовки: {', '.join(found)}"
                    return base_result

            elif cond_type == "cookie_flags":
                resp = await client.get(f"{self.base_url}/")
                cookies = resp.headers.get("set-cookie", "")
                flags = condition.get("check_flags", ["Secure", "HttpOnly"])
                missing = [f for f in flags if f.lower() not in cookies.lower()]
                if missing and cookies:
                    base_result["evidence"] = f"У cookies отсутствуют флаги: {', '.join(missing)}"
                    return base_result

            elif cond_type == "cors":
                origin = condition.get("origin", "https://evil.com")
                resp = await client.get(f"{self.base_url}/", headers={"Origin": origin})
                allow_origin = resp.headers.get("Access-Control-Allow-Origin", "")
                if allow_origin == "*" or allow_origin == origin:
                    base_result["evidence"] = f"CORS разрешает запросы с {origin}"
                    return base_result

            # --- ПРОВЕРКИ АУТЕНТИФИКАЦИИ И АВТОРИЗАЦИИ ---
            elif cond_type == "missing_auth":
                for endpoint in endpoints:
                    resp = await client.get(f"{self.base_url}{endpoint}")
                    if resp.status_code not in condition.get("expected_status", [401, 403]):
                        base_result["endpoint"] = endpoint
                        base_result["evidence"] = f"Эндпоинт доступен без аутентификации (статус {resp.status_code})"
                        return base_result

            elif cond_type == "invalid_token" or cond_type == "jwt_algorithm":
                tokens = condition.get("test_tokens", condition.get("test_algorithms", ["invalid_token"]))
                for endpoint in endpoints[:3]:
                    for token in tokens:
                        resp = await client.get(f"{self.base_url}{endpoint}", headers={"Authorization": f"Bearer {token}"})
                        if resp.status_code not in condition.get("expected_status", [401, 403]):
                            base_result["endpoint"] = endpoint
                            base_result["evidence"] = f"Доступ разрешён с токеном/алгоритмом '{token}'"
                            return base_result

            elif cond_type == "brute_force":
                endpoint = condition.get("endpoint", "/login")
                attempts = condition.get("attempts", 10)
                status_codes = []
                for _ in range(attempts):
                    resp = await client.post(f"{self.base_url}{endpoint}", json={"username": "admin", "password": "wrong"})
                    status_codes.append(resp.status_code)
                if condition.get("expected_status") not in status_codes:
                    base_result["endpoint"] = endpoint
                    base_result["evidence"] = f"Нет защиты от перебора после {attempts} попыток"
                    return base_result

            elif cond_type == "rate_limit":
                count = condition.get("requests_count", 50)
                status_codes = []
                for _ in range(count):
                    resp = await client.get(f"{self.base_url}/")
                    status_codes.append(resp.status_code)
                if condition.get("expected_status") not in status_codes:
                    base_result["evidence"] = f"Сервер не вернул статус {condition.get('expected_status')} после {count} запросов"
                    return base_result

            # --- ИНЪЕКЦИИ И ПЕЙЛОАДЫ ---
            elif cond_type in ["sql_injection", "xss_reflected", "ssrf", "path_traversal", "command_injection", "xxe", "json_injection"]:
                payloads = condition.get("payloads", [])
                
                # Паттерны для обнаружения уязвимостей
                sql_patterns = ["sql", "syntax", "sqlite", "mysql", "postgresql", "ora-", "unclosed quotation", "sqlstate"]
                xss_patterns = ["<script>", "alert(", "onerror=", "<img", "javascript:"]
                ssrf_patterns = ["localhost", "127.0.0.1", "169.254.169.254", "meta-data", "internal"]
                path_patterns = ["root:", "bin/bash", "windows", "system32", "[boot loader]"]
                cmd_patterns = ["uid=", "gid=", "www-data", "root:", "total ", "drwx"]
                
                for endpoint in endpoints:
                    for payload in payloads:
                        # Проверка в query-параметрах
                        try:
                            resp = await client.get(f"{self.base_url}{endpoint}", params={"q": payload, "username": payload, "name": payload, "file": payload, "url": payload, "host": payload, "filename": payload}, timeout=10.0)
                            response_text = resp.text.lower()
                            
                            # SQL Injection — ищем SQL-ошибки
                            if cond_type == "sql_injection":
                                if any(p in response_text for p in sql_patterns):
                                    base_result["endpoint"] = endpoint
                                    base_result["evidence"] = f"SQL-инъекция: пейлоад '{payload}' вызвал SQL-ошибку в ответе"
                                    return base_result
                            
                            # XSS — проверяем отражение пейлоада
                            elif cond_type == "xss_reflected":
                                if payload.lower() in response_text:
                                    base_result["endpoint"] = endpoint
                                    base_result["evidence"] = f"XSS: пейлоад '{payload}' отразился в ответе без экранирования"
                                    return base_result
                            
                            # SSRF — проверяем доступ к внутренним ресурсам
                            elif cond_type == "ssrf":
                                if any(p in response_text for p in ssrf_patterns):
                                    base_result["endpoint"] = endpoint
                                    base_result["evidence"] = f"SSRF: сервер сделал запрос к внутреннему ресурсу '{payload}'"
                                    return base_result
                            
                            # Path Traversal — проверяем чтение системных файлов
                            elif cond_type == "path_traversal":
                                if any(p in response_text for p in path_patterns):
                                    base_result["endpoint"] = endpoint
                                    base_result["evidence"] = f"Path Traversal: прочитан системный файл через пейлоад '{payload}'"
                                    return base_result
                            
                            # Command Injection — проверяем выполнение команд
                            elif cond_type == "command_injection":
                                if any(p in response_text for p in cmd_patterns):
                                    base_result["endpoint"] = endpoint
                                    base_result["evidence"] = f"Command Injection: выполнена системная команда через пейлоад '{payload}'"
                                    return base_result
                            
                            # XXE — проверяем чтение файлов через XML
                            elif cond_type == "xxe":
                                if any(p in response_text for p in path_patterns):
                                    base_result["endpoint"] = endpoint
                                    base_result["evidence"] = f"XXE: прочитан файл через внешнюю сущность"
                                    return base_result
                            
                            # JSON Injection — проверяем изменение структуры
                            elif cond_type == "json_injection":
                                if resp.status_code == 200:
                                    try:
                                        data = resp.json()
                                        if "admin" in str(data).lower() or "role" in str(data).lower():
                                            base_result["endpoint"] = endpoint
                                            base_result["evidence"] = f"JSON Injection: пейлоад '{payload}' изменил структуру ответа"
                                            return base_result
                                    except:
                                        pass
                        
                        except Exception as e:
                            pass
                        
                        # Проверка в теле запроса (POST)
                        try:
                            if cond_type == "xxe":
                                resp = await client.post(f"{self.base_url}{endpoint}", content=payload, headers={"Content-Type": "application/xml"}, timeout=10.0)
                            else:
                                resp = await client.post(f"{self.base_url}{endpoint}", json={"data": payload, "username": payload, "name": payload, "file": payload, "url": payload, "host": payload, "filename": payload}, timeout=10.0)
                            
                            response_text = resp.text.lower()
                            
                            if cond_type == "sql_injection" and any(p in response_text for p in sql_patterns):
                                base_result["endpoint"] = endpoint
                                base_result["evidence"] = f"SQL-инъекция: пейлоад '{payload}' вызвал SQL-ошибку"
                                return base_result
                            elif cond_type == "xss_reflected" and payload.lower() in response_text:
                                base_result["endpoint"] = endpoint
                                base_result["evidence"] = f"XSS: пейлоад '{payload}' отразился в ответе"
                                return base_result
                            elif cond_type == "ssrf" and any(p in response_text for p in ssrf_patterns):
                                base_result["endpoint"] = endpoint
                                base_result["evidence"] = f"SSRF: сервер сделал запрос к '{payload}'"
                                return base_result
                            elif cond_type == "path_traversal" and any(p in response_text for p in path_patterns):
                                base_result["endpoint"] = endpoint
                                base_result["evidence"] = f"Path Traversal: прочитан файл через '{payload}'"
                                return base_result
                            elif cond_type == "command_injection" and any(p in response_text for p in cmd_patterns):
                                base_result["endpoint"] = endpoint
                                base_result["evidence"] = f"Command Injection: выполнена команда через '{payload}'"
                                return base_result
                        
                        except Exception as e:
                            pass
            # --- ЛОГИЧЕСКИЕ УЯЗВИМОСТИ ---
            elif cond_type == "bola" or cond_type == "idor_param":
                # Проверяем BOLA/IDOR через подмену ID
                test_endpoints = ["/users/1", "/users/2", "/posts/1", "/products/1"]
                for endpoint in test_endpoints:
                    try:
                        resp1 = await client.get(f"{self.base_url}{endpoint}", timeout=10.0)
                        alt_endpoint = endpoint.replace("/1", "/2").replace("/2", "/999999")
                        resp2 = await client.get(f"{self.base_url}{alt_endpoint}", timeout=10.0)
                        
                        if resp1.status_code == 200 and resp2.status_code == 200:
                            try:
                                data1 = resp1.json()
                                data2 = resp2.json()
                                # Если данные разные — значит IDOR есть
                                if data1 != data2 and "id" in str(data1):
                                    base_result["endpoint"] = endpoint
                                    base_result["evidence"] = f"IDOR/BOLA: доступ к объекту {alt_endpoint} без проверки прав"
                                    return base_result
                            except:
                                pass
                    except:
                        pass

            elif cond_type == "mass_assignment":
                fields = condition.get("fields", ["isAdmin", "role", "permissions"])
                test_endpoints = ["/users/1", "/users/2", "/profile/1"]
                
                for endpoint in test_endpoints:
                    try:
                        # Пытаемся изменить привилегированные поля
                        payload = {"role": "admin", "isAdmin": True, "permissions": ["all"]}
                        resp = await client.patch(f"{self.base_url}{endpoint}", json=payload, timeout=10.0)
                        
                        if resp.status_code == 200:
                            try:
                                data = resp.json()
                                # Проверяем, изменились ли поля
                                if data.get("role") == "admin" or data.get("isAdmin") == True:
                                    base_result["endpoint"] = endpoint
                                    base_result["evidence"] = f"Mass Assignment: удалось изменить привилегированные поля {fields}"
                                    return base_result
                            except:
                                pass
                    except:
                        pass

            elif cond_type in ["excessive_data", "excessive_data_list"]:
                sensitive_fields = condition.get("sensitive_fields", ["password", "email", "phone", "token", "secret", "api_key", "internal_id"])
                test_endpoints = ["/users/1", "/users/2", "/profile/1", "/debug", "/api/data"]
                
                for endpoint in test_endpoints:
                    try:
                        resp = await client.get(f"{self.base_url}{endpoint}", timeout=10.0)
                        if resp.status_code == 200:
                            try:
                                data = resp.json()
                                data_str = str(data).lower()
                                found = [f for f in sensitive_fields if f in data_str]
                                if found:
                                    base_result["endpoint"] = endpoint
                                    base_result["evidence"] = f"Раскрыты чувствительные поля: {', '.join(found)}"
                                    return base_result
                            except:
                                pass
                    except:
                        pass

            # --- ОШИБКИ И ДИАГНОСТИКА ---
            elif cond_type == "verbose_errors" or cond_type == "debug_mode":
                trigger = condition.get("trigger_payload", "invalid_json{{")
                resp = await client.post(f"{self.base_url}/", content=trigger, headers={"Content-Type": "application/json"})
                patterns = condition.get("check_patterns", [])
                for pattern in patterns:
                    if pattern.lower() in resp.text.lower():
                        base_result["evidence"] = f"Найден паттерн '{pattern}' в ответе"
                        return base_result

            elif cond_type == "http_methods":
                methods = condition.get("methods", ["TRACE", "PUT", "DELETE"])
                for method in methods:
                    resp = await client.request(method, f"{self.base_url}/")
                    if resp.status_code not in condition.get("expected_status", [405, 501]):
                        base_result["evidence"] = f"Метод {method} разрешен (статус {resp.status_code})"
                        return base_result

            # --- REDIRECT И URL ---
            elif cond_type in ["open_redirect", "unvalidated_redirect"]:
                payloads = condition.get("payloads", ["https://evil.com"])
                for endpoint in endpoints:
                    for payload in payloads:
                        resp = await client.get(f"{self.base_url}{endpoint}", params={"url": payload, "redirect": payload}, follow_redirects=False)
                        location = resp.headers.get("Location", "")
                        if payload in location:
                            base_result["endpoint"] = endpoint
                            base_result["evidence"] = f"Открытый редирект на {payload}"
                            return base_result

            elif cond_type in ["sensitive_url", "api_key_url"]:
                # Проверяем, не светятся ли чувствительные параметры в URL (базовая эвристика)
                pass 

            # --- GRAPHQL ---
            elif cond_type == "graphql_introspection":
                query = condition.get("query", '{ "__schema": { "types": { "name" } } }')
                resp = await client.post(f"{self.base_url}/graphql", json={"query": query})
                if resp.status_code == 200 and "__schema" in resp.text:
                    base_result["endpoint"] = "/graphql"
                    base_result["evidence"] = "Инtrospection GraphQL включена"
                    return base_result

            elif cond_type == "graphql_depth":
                depth = condition.get("depth", 20)
                query = "{" + "a{" * depth + "name" + "}" * depth + "}"
                resp = await client.post(f"{self.base_url}/graphql", json={"query": query})
                if resp.status_code != condition.get("expected_status", 400):
                    base_result["endpoint"] = "/graphql"
                    base_result["evidence"] = f"GraphQL принял запрос с глубиной {depth}"
                    return base_result

            # --- DoS И PAYLOAD ---
            elif cond_type == "large_payload":
                size_mb = condition.get("size_mb", 10)
                large_data = "A" * (size_mb * 1024 * 1024)
                resp = await client.post(f"{self.base_url}/", content=large_data, headers={"Content-Type": "application/octet-stream"})
                if resp.status_code != condition.get("expected_status", 413):
                    base_result["evidence"] = f"Сервер принял большой payload ({size_mb}MB) без ошибки"
                    return base_result

            elif cond_type == "content_type":
                test_type = condition.get("test_type", "application/xml")
                resp = await client.post(f"{self.base_url}/", content="<xml></xml>", headers={"Content-Type": test_type})
                if resp.status_code != condition.get("expected_status", 415):
                    base_result["evidence"] = f"Сервер принял неверный Content-Type: {test_type}"
                    return base_result

        except Exception as e:
            pass

        return None
