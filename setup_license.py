import os

# 1. Создаём файл с лицензионным ключом (заглушка)
license_key = "PREMIUM-2026-ABCD-1234-EFGH-5678"
with open('license.key', 'w', encoding='utf-8') as f:
    f.write(license_key)

print(f"✅ Создан файл license.key с ключом: {license_key}")

# 2. Добавляем в main_window.py автозагрузку ключа
with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Добавляем импорт os в начало если нет
if 'import os' not in content:
    content = content.replace('import sys', 'import sys\nimport os')

# Находим место где загружаются настройки и добавляем проверку лицензии
old_init = """        self.settings = load_settings()
        self.setWindowTitle"""

new_init = """        self.settings = load_settings()
        
        # Автозагрузка лицензионного ключа из файла
        license_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'license.key')
        if os.path.exists(license_file):
            try:
                with open(license_file, 'r', encoding='utf-8') as f:
                    saved_key = f.read().strip()
                    if saved_key:
                        self.settings['license_key'] = saved_key
                        save_settings(self.settings)
                        print(f"✅ Лицензионный ключ загружен из файла")
            except Exception as e:
                print(f"⚠️ Не удалось загрузить license.key: {e}")
        
        self.setWindowTitle"""

content = content.replace(old_init, new_init)

with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("✅ desktop_app/main_window.py: Добавлена автозагрузка license.key")
