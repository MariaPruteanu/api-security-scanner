import re

with open('scanner/core.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Безжалостно удаляем любую строку, где есть load_specification
content = re.sub(r'^.*load_specification.*\n', '', content, flags=re.MULTILINE)

# 2. Если правильный импорт RulesLoader был случайно удалён, возвращаем его
if 'from .rules_loader import RulesLoader' not in content:
    # Находим первый import и добавляем RulesLoader сразу после него
    content = re.sub(r'^(import .*)\n', r'\1\nfrom .rules_loader import RulesLoader\n', content, count=1)
    print("✅ Импорт RulesLoader восстановлен!")
else:
    print("✅ Импорт RulesLoader уже на месте!")

with open('scanner/core.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("✅ scanner/core.py полностью исправлен!")
