with open('scanner/rules_loader.py', 'r', encoding='utf-8') as f:
    content = f.read()

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
    print("✅ scanner/rules_loader.py: Путь к правилам исправлен для PyInstaller!")
else:
    print("⚠️ Блок не найден. Возможно, он уже изменён.")
