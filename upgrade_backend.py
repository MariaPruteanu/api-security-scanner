import re

with open('scanner/core.py', 'r', encoding='utf-8') as f:
    core = f.read()

# 1. Исправляем ошибку 'spec is not defined'
# Если spec не загрузился, делаем его пустым словарем, чтобы код не падал
if 'if spec is None:' not in core:
    core = re.sub(
        r'(spec\s*=\s*await\s*self\._fetch_openapi\(\))',
        r'\1\n            if spec is None:\n                spec = {}',
        core
    )
    print("✅ Ошибка 'spec is not defined' исправлена.")

# 2. Добавляем поле 'remediation' (Как исправить) в результаты
# Ищем место, где формируется словарь уязвимости (обычно там есть 'severity')
if "'remediation'" not in core:
    core = re.sub(
        r"('severity':\s*[^,]+,)",
        r"\1\n                    'remediation': rule.get('remediation', rule.get('fix', 'См. документацию OWASP API Security Top 10')),",
        core
    )
    print("✅ Поле 'Как исправить' (remediation) добавлено в результаты.")

with open('scanner/core.py', 'w', encoding='utf-8') as f:
    f.write(core)
