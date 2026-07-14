import sys
import re

filename = "main_window.py"
with open(filename, 'r') as f:
    lines = f.readlines()

# Удалим все старые определения _load_keys и вызовы
new_lines = []
for line in lines:
    if 'def _load_keys' not in line and 'self._load_keys()' not in line:
        new_lines.append(line)
lines = new_lines

# Найдём последний метод класса MainWindow (строка с '    def ')
last_method_index = None
for i in range(len(lines)-1, -1, -1):
    if re.match(r'^    def ', lines[i]):
        last_method_index = i
        break

if last_method_index is None:
    print("❌ Не найден метод класса MainWindow")
    sys.exit(1)

# Вставляем метод _load_keys перед последним методом
indent = '    '
method_lines = [
    f'\n{indent}def _load_keys(self):',
    f'{indent}    """Загружает ключи из файлов и применяет их."""',
    f'{indent}    try:',
    f'{indent}        import os, sys',
    f'{indent}        if getattr(sys, "frozen", False):',
    f'{indent}            base = sys._MEIPASS',
    f'{indent}        else:',
    f'{indent}            base = os.path.dirname(os.path.abspath(__file__))',
    f'{indent}        for key_file, key_name in [("premium_key.txt", "premium"), ("enterprise_key.txt", "enterprise"), ("api_key.txt", "api")]:',
    f'{indent}            path = os.path.join(base, "config", key_file)',
    f'{indent}            if os.path.exists(path):',
    f'{indent}                with open(path, "r") as f:',
    f'{indent}                    key = f.read().strip()',
    f'{indent}                    if key_name == "api":',
    f'{indent}                        self.api_key = key',
    f'{indent}                        if hasattr(self, "api_key_input"):',
    f'{indent}                            self.api_key_input.setText(key)',
    f'{indent}                        self.settings["api_key"] = key',
    f'{indent}                    else:',
    f'{indent}                        self.license_valid[key_name] = True',
    f'{indent}                        self.settings[f"{key_name}_key"] = key',
    f'{indent}        self.update_usage_status()',
    f'{indent}        print("[DEBUG] _load_keys: ключи успешно загружены")',
    f'{indent}    except Exception as e:',
    f'{indent}        print(f"[ERROR] _load_keys: {{e}}")',
]
lines = lines[:last_method_index] + method_lines + lines[last_method_index:]

# Добавляем вызов self._load_keys() в __init__ после self.on_mode_changed(0)
insert_after = None
for i, line in enumerate(lines):
    if 'self.on_mode_changed(0)' in line:
        insert_after = i
        break

if insert_after is None:
    # Если не нашли, ищем последнюю строку внутри __init__ (отступ 8 пробелов)
    for i in range(len(lines)-1, -1, -1):
        if lines[i].startswith('        ') and 'def ' not in lines[i] and i > 0:
            insert_after = i
            break

if insert_after is not None:
    already_has = False
    for j in range(insert_after+1, min(insert_after+5, len(lines))):
        if 'self._load_keys()' in lines[j]:
            already_has = True
            break
    if not already_has:
        indent_init = ' ' * (len(lines[insert_after]) - len(lines[insert_after].lstrip()))
        lines.insert(insert_after+1, f'{indent_init}# Загружаем ключи из файлов (после создания интерфейса)\n')
        lines.insert(insert_after+2, f'{indent_init}self._load_keys()\n')
        print("✅ Вызов _load_keys добавлен в __init__")
else:
    print("❌ Не найдено место для вставки вызова _load_keys")

with open(filename, 'w') as f:
    f.writelines(lines)

print("✅ Готово! Метод _load_keys добавлен и вызов вставлен.")
