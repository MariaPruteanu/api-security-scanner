with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Ищем две команды, слипшиеся в одну строку
old = 'scanner = APIScanner(base_url=self.target, timeout=self.timeout, scan_type=self.scan_type)                    self.log("⏳ Выполняется сканирование...")'

new = '''scanner = APIScanner(base_url=self.target, timeout=self.timeout, scan_type=self.scan_type)
                    self.log("⏳ Выполняется сканирование...")'''

if old in content:
    content = content.replace(old, new)
    with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("✅ Строка 229 исправлена!")
else:
    print("⚠️ Не удалось найти слипшиеся команды. Проверь файл вручную.")
