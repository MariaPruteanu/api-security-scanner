with open('scanner/core.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_code = """                if response.status == 200:
                    spec = await response.json()
                    version = spec.get('openapi', spec.get('swagger', 'unknown'))"""

new_code = """                if response.status == 200:
                    spec = await response.json()
                    if spec is None:
                        print("⚠️ Спецификация пуста", file=sys.stderr)
                        return {}
                    version = spec.get('openapi', spec.get('swagger', 'unknown'))"""

if old_code in content:
    content = content.replace(old_code, new_code)
    with open('scanner/core.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("✅ scanner/core.py: Добавлена защита от None")
else:
    print("⚠️ Блок не найден (возможно, уже изменён или форматирование отличается)")
