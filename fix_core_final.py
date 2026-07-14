with open('scanner/core.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_code = """    async def _fetch_openapi(self) -> Optional[Dict]:
        try:
            loop = asyncio.get_event_loop()
            spec = None  # load_specification временно отключена
            if spec:
                version = spec.get('openapi', spec.get('swagger', 'unknown'))
                print(f"📄 Загружена спецификация, версия: {version}", file=sys.stderr)
            else:
                print("⚠️ Спецификация не загружена (временная заглушка)", file=sys.stderr)
            return spec
        except Exception as e:
            print(f"⚠️ Ошибка загрузки спецификации: {e}", file=sys.stderr)
            return None"""

new_code = """    async def _fetch_openapi(self) -> Optional[Dict]:
        try:
            # Скачиваем спецификацию напрямую через aiohttp
            async with self.session.get(self.base_url, timeout=self.timeout) as response:
                if response.status == 200:
                    spec = await response.json()
                    version = spec.get('openapi', spec.get('swagger', 'unknown'))
                    print(f"📄 Загружена спецификация, версия: {version}", file=sys.stderr)
                    return spec
                else:
                    print(f"⚠️ Не удалось загрузить спецификацию, статус: {response.status}", file=sys.stderr)
                    return None
        except Exception as e:
            print(f"⚠️ Ошибка загрузки спецификации: {e}", file=sys.stderr)
            return None"""

if old_code in content:
    content = content.replace(old_code, new_code)
    with open('scanner/core.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("✅ Метод _fetch_openapi успешно восстановлен!")
else:
    print("⚠️ Не удалось найти старый код. Возможно, он уже изменён. Проверь scanner/core.py вручную.")
