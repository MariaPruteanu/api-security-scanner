import sys
import re

filename = "main_window.py"
with open(filename, 'r') as f:
    lines = f.readlines()

# Находим строку self.on_mode_changed(0)
target_index = None
for i, line in enumerate(lines):
    if 'self.on_mode_changed(0)' in line:
        target_index = i
        break

if target_index is None:
    print("❌ Не найдена строка self.on_mode_changed(0)")
    sys.exit(1)

# Проверяем, есть ли уже вызов _load_keys() после неё
has_load_keys = False
for i in range(target_index + 1, min(target_index + 5, len(lines))):
    if '_load_keys()' in lines[i]:
        has_load_keys = True
        break

if has_load_keys:
    print("✅ _load_keys() уже вызывается после on_mode_changed, проверяем наличие метода...")
else:
    # Вставляем вызов _load_keys() после строки
    indent = ' ' * (len(lines[target_index]) - len(lines[target_index].lstrip()))
    insert_lines = [
        f'{indent}# Загружаем ключи из файлов (после создания интерфейса)\n',
        f'{indent}self._load_keys()\n',
    ]
    lines = lines[:target_index+1] + insert_lines + lines[target_index+1:]
    print("✅ Вызов _load_keys() добавлен в __init__")

# Проверяем, что метод _load_keys определён в классе
has_method = False
for i, line in enumerate(lines):
    if 'def _load_keys(self):' in line:
        has_method = True
        break

if not has_method:
    print("❌ Метод _load_keys не найден, добавляем...")
    # Находим конец класса MainWindow (последний метод)
    # Ищем def closeEvent или другой метод в конце класса
    insert_index = None
    for i in range(len(lines)-1, -1, -1):
        if 'def closeEvent' in lines[i] or 'def buy_pro' in lines[i]:
            insert_index = i
            break
    if insert_index is None:
        # Ищем последний метод в классе
        for i in range(len(lines)-1, -1, -1):
            if 'def ' in lines[i] and 'self' in lines[i]:
                insert_index = i
                break
    if insert_index is not None:
        indent = ' ' * 4
        method_lines = [
            f'\n{indent}def _load_keys(self):\n',
            f'{indent}    """Загружает ключи из файлов и применяет их."""\n',
            f'{indent}    try:\n',
            f'{indent}        import os, sys\n',
            f'{indent}        if getattr(sys, "frozen", False):\n',
            f'{indent}            base = sys._MEIPASS\n',
            f'{indent}        else:\n',
            f'{indent}            base = os.path.dirname(os.path.abspath(__file__))\n',
            f'{indent}        for key_file, key_name in [("premium_key.txt", "premium"), ("enterprise_key.txt", "enterprise"), ("api_key.txt", "api")]:\n',
            f'{indent}            path = os.path.join(base, "config", key_file)\n',
            f'{indent}            if os.path.exists(path):\n',
            f'{indent}                with open(path, "r") as f:\n',
            f'{indent}                    key = f.read().strip()\n',
            f'{indent}                    if key_name == "api":\n',
            f'{indent}                        self.api_key = key\n',
            f'{indent}                        if hasattr(self, "api_key_input"):\n',
            f'{indent}                            self.api_key_input.setText(key)\n',
            f'{indent}                        self.settings["api_key"] = key\n',
            f'{indent}                    else:\n',
            f'{indent}                        self.license_valid[key_name] = True\n',
            f'{indent}                        self.settings[f"{key_name}_key"] = key\n',
            f'{indent}        self.update_usage_status()\n',
            f'{indent}        print("[DEBUG] _load_keys: ключи успешно загружены")\n',
            f'{indent}    except Exception as e:\n',
            f'{indent}        print(f"[ERROR] _load_keys: {e}")\n',
        ]
        lines = lines[:insert_index+1] + method_lines + lines[insert_index+1:]
        print("✅ Метод _load_keys добавлен в класс MainWindow")

with open(filename, 'w') as f:
    f.writelines(lines)

print("✅ Готово! Пересобирайте приложение.")
