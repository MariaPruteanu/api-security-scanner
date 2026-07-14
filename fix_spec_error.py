import re

with open('scanner/core.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Находим метод _fetch_openapi и полностью заменяем его на рабочий
new_fetch_method = '''    async def _fetch_openapi(self) -> Optional[Dict]:
        try:
            print(f"📥 Загрузка спецификации из: {self.base_url}", file=sys.stderr)
            headers = {'Accept': 'application/json, */*'}
            async with self.session.get(self.base_url, headers=headers, timeout=self.timeout) as response:
                print(f"📡 Статус ответа: {response.status}", file=sys.stderr)
                if response.status == 200:
                    text = await response.text()
                    print(f"📄 Получено байт: {len(text)}", file=sys.stderr)
                    try:
                        spec = await response.json()
                        if spec and isinstance(spec, dict):
                            version = spec.get('openapi', spec.get('swagger', 'unknown'))
                            paths = spec.get('paths', {})
                            print(f"✅ Загружена спецификация, версия: {version}", file=sys.stderr)
                            print(f"🔗 Найдено путей: {len(paths)}", file=sys.stderr)
                            return spec
                        else:
                            print("⚠️ Спецификация не является JSON-объектом", file=sys.stderr)
                            return {}
                    except Exception as json_err:
                        print(f"⚠️ Ошибка парсинга JSON: {json_err}", file=sys.stderr)
                        return {}
                else:
                    print(f"⚠️ Не удалось загрузить спецификацию, статус: {response.status}", file=sys.stderr)
                    return {}
        except Exception as e:
            print(f"⚠️ Ошибка загрузки спецификации: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            return {}
'''

# Ищем старый метод и заменяем
pattern = r'(    async def _fetch_openapi\(self\) -> Optional\[Dict\]:.*?)(?=\n    async def |\n    def |\nclass |\Z)'
match = re.search(pattern, content, re.DOTALL)
if match:
    content = content[:match.start()] + new_fetch_method + content[match.end():]
    with open('scanner/core.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("✅ Метод _fetch_openapi полностью переписан!")
else:
    print("⚠️ Метод не найден")
