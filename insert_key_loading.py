import sys
import os
import re

filename = "main_window.py"
with open(filename, 'r') as f:
    lines = f.readlines()

# Находим строку def open_settings
target_index = None
for i, line in enumerate(lines):
    if re.match(r'^\s*def open_settings', line):
        target_index = i
        break

if target_index is None:
    print("Не найдена строка def open_settings")
    sys.exit(1)

# Проверяем, есть ли уже блок загрузки ключей
for line in lines:
    if 'Принудительная загрузка ключей из файлов' in line:
        print("Блок уже существует, пропускаем")
        sys.exit(0)

# Отступ для блока (4 пробела, т.к. внутри __init__)
indent = '        '  # 8 пробелов (так как внутри __init__)

# Блок для вставки
insert_block = [
    f'{indent}# Принудительная загрузка ключей из файлов (в конце __init__)\n',
    f'{indent}try:\n',
    f'{indent}    import os, sys\n',
    f'{indent}    if getattr(sys, "frozen", False):\n',
    f'{indent}        base = sys._MEIPASS\n',
    f'{indent}    else:\n',
    f'{indent}        base = os.path.dirname(os.path.abspath(__file__))\n',
    f'{indent}    for key_file, key_name in [("premium_key.txt", "premium"), ("enterprise_key.txt", "enterprise"), ("api_key.txt", "api")]:\n',
    f'{indent}        path = os.path.join(base, "config", key_file)\n',
    f'{indent}        if os.path.exists(path):\n',
    f'{indent}            with open(path, "r") as f:\n',
    f'{indent}                key = f.read().strip()\n',
    f'{indent}                if key_name == "api":\n',
    f'{indent}                    self.api_key = key\n',
    f'{indent}                    self.api_key_input.setText(key)\n',
    f'{indent}                    self.settings["api_key"] = key\n',
    f'{indent}                else:\n',
    f'{indent}                    self.license_valid[key_name] = True\n',
    f'{indent}                    self.settings[f"{key_name}_key"] = key\n',
    f'{indent}    self.update_usage_status()\n',
    f'{indent}except Exception as e:\n',
    f'{indent}    print(f"[ERROR] Загрузка ключей не удалась: {e}")\n',
]

# Вставляем блок перед target_index
new_lines = lines[:target_index] + insert_block + lines[target_index:]

with open(filename, 'w') as f:
    f.writelines(new_lines)

print("✅ Блок загрузки ключей добавлен перед def open_settings")
