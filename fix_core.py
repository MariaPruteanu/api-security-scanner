with open('scanner/core.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_code = """    async def _fetch_openapi(self) -> Optional[Dict]:
        try:
            loop = asyncio.get_event_loop()
            spec = None  # load_specification временно отключена
            version = spec.get('openapi', spec.get('swagger', 'unknown'))
            print(f"📄 Загружена спецификация, версия: {version}", file=sys.stderr)
            return spec
        except Exception as e:
            print(f"⚠️ Ошибка загрузки спецификации: {e}", file=sys.stderr)
            return None"""

new_code = """    async def _fetch_openapi(self) -> Optional[Dict]:
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

content = content.replace(old_code, new_code)

with open('scanner/core.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("✅ Файл scanner/core.py успешно исправлен!")
