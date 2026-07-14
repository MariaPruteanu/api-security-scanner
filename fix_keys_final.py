import sys
import re

filename = "main_window.py"

# Читаем файл
with open(filename, 'r') as f:
    lines = f.readlines()

# 1. Удаляем все строки, содержащие "_load_keys" (кроме комментариев)
new_lines = []
for line in lines:
    if '_load_keys' not in line:
        new_lines.append(line)
lines = new_lines

# 2. Находим строку с глобальной def run() (вне класса)
run_index = None
for i, line in enumerate(lines):
    if line.strip().startswith('def run()') and not line.startswith(' '):
        run_index = i
        break

if run_index is None:
    print("❌ Не найдена глобальная def run()")
    sys.exit(1)

# 3. Создаём метод _load_keys с правильным отступом (4 пробела)
method_lines = [
    '    def _load_keys(self):\n',
    '        """Загружает ключи из файлов и применяет их."""\n',
    '        try:\n',
    '            import os, sys\n',
    '            if getattr(sys, "frozen", False):\n',
    '                base = sys._MEIPASS\n',
    '            else:\n',
    '                base = os.path.dirname(os.path.abspath(__file__))\n',
    '            for key_file, key_name in [("premium_key.txt", "premium"), ("enterprise_key.txt", "enterprise"), ("api_key.txt", "api")]:\n',
    '                path = os.path.join(base, "config", key_file)\n',
    '                if os.path.exists(path):\n',
    '                    with open(path, "r") as f:\n',
    '                        key = f.read().strip()\n',
    '                        if key_name == "api":\n',
    '                            self.api_key = key\n',
    '                            if hasattr(self, "api_key_input"):\n',
    '                                self.api_key_input.setText(key)\n',
    '                            self.settings["api_key"] = key\n',
    '                        else:\n',
    '                            self.license_valid[key_name] = True\n',
    '                            self.settings[f"{key_name}_key"] = key\n',
    '            self.update_usage_status()\n',
    '            print("[DEBUG] _load_keys: ключи успешно загружены")\n',
    '        except Exception as e:\n',
    '            print(f"[ERROR] _load_keys: {e}")\n',
]

# Вставляем метод перед def run()
lines = lines[:run_index] + method_lines + lines[run_index:]

# 4. Находим строку self.on_mode_changed(0) в __init__
insert_after = None
for i, line in enumerate(lines):
    if 'self.on_mode_changed(0)' in line:
        insert_after = i
        break

if insert_after is not None:
    # Определяем отступ (пробелы перед строкой)
    indent = re.match(r'^(\s*)', lines[insert_after]).group(1)
    # Вставляем вызов
    lines.insert(insert_after+1, f'{indent}# Загружаем ключи из файлов (после создания интерфейса)\n')
    lines.insert(insert_after+2, f'{indent}self._load_keys()\n')
    print("✅ Вызов _load_keys добавлен в __init__")
else:
    print("❌ Не найдена строка self.on_mode_changed(0)")

# Записываем обновлённый файл
with open(filename, 'w') as f:
    f.writelines(lines)

print("✅ Файл исправлен")
