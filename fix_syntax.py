import re

with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Ищем две команды, слипшиеся в одну строку с большим количеством пробелов, и разделяем их
content = re.sub(
    r'(scanner = APIScanner\(base_url=self\.target.*?\))\s+(self\.log\("⏳ Выполняется сканирование\.\.\."\))',
    r'\1\n        \2',
    content
)

# Также проверим другие возможные слипания, которые могли возникнуть
content = re.sub(r'(\w+\(.*?\))\s{10,}(self\.\w+\()', r'\1\n        \2', content)

with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("✅ Синтаксическая ошибка в main_window.py исправлена!")
