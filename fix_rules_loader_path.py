with open('scanner/rules_loader.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Добавляем import sys в самое начало, если его нет
if 'import sys' not in content:
    content = 'import sys\n' + content

# 2. Заменяем старую логику поиска папки на новую, совместимую с PyInstaller
old_code = """        if rules_dir is None:
            # Корень проекта – это папка, содержащая папку scanner
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.rules_dir = os.path.join(base_dir, "rules")"""

new_code = """        if rules_dir is None:
            # Поддержка PyInstaller: используем sys._MEIPASS если приложение упаковано
            import sys
            if getattr(sys, 'frozen', False):
                base_dir = sys._MEIPASS
            else:
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            # Правила лежат в папке scanner/rules
            self.rules_dir = os.path.join(base_dir, "scanner", "rules")"""

if old_code in content:
    content = content.replace(old_code, new_code)
    with open('scanner/rules_loader.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("✅ rules_loader.py исправлен для работы внутри PyInstaller!")
else:
    print("⚠️ Не удалось найти старый код. Возможно, он уже изменён.")
