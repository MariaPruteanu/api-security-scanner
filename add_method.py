import sys
import re

filename = "main_window.py"
with open(filename, 'r') as f:
    lines = f.readlines()

# Найдём последний метод класса MainWindow (поищем def, начиная с конца)
insert_index = None
for i in range(len(lines)-1, -1, -1):
    # Ищем строки, которые начинаются с def и имеют отступ 4 пробела (внутри класса)
    if re.match(r'^    def ', lines[i]):
        insert_index = i
        break

if insert_index is None:
    print("❌ Не найден метод класса MainWindow")
    sys.exit(1)

# Проверяем, есть ли уже метод _load_keys
for line in lines:
    if 'def _load_keys' in line:
        print("✅ Метод _load_keys уже существует, ничего не делаем")
        sys.exit(0)

# Определяем метод
indent = '    '
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
    f'{indent}        print(f"[ERROR] _load_keys: {{e}}")\n',
]

# Вставляем метод перед последним методом
new_lines = lines[:insert_index] + method_lines + lines[insert_index:]

with open(filename, 'w') as f:
    f.writelines(new_lines)

print("✅ Метод _load_keys добавлен в класс MainWindow")
