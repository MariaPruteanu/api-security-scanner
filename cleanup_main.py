import sys
import re

filename = "main_window.py"
with open(filename, 'r') as f:
    lines = f.readlines()

# Удалим все строки, содержащие "Загружаем ключи из файлов" и "self._load_keys()" (кроме определений метода)
new_lines = []
skip = False
for line in lines:
    if '# Загружаем ключи из файлов' in line:
        continue
    if 'self._load_keys()' in line:
        continue
    new_lines.append(line)

# Теперь добавим один вызов в конец __init__ (после self.on_mode_changed(0))
# Найдём строку self.on_mode_changed(0) и вставим после неё
target_index = None
for i, line in enumerate(new_lines):
    if 'self.on_mode_changed(0)' in line:
        target_index = i
        break

if target_index is not None:
    indent = ' ' * (len(new_lines[target_index]) - len(new_lines[target_index].lstrip()))
    insert_lines = [
        f'{indent}# Загружаем ключи из файлов\n',
        f'{indent}self._load_keys()\n',
    ]
    new_lines = new_lines[:target_index+1] + insert_lines + new_lines[target_index+1:]

# Проверим, что определение метода _load_keys присутствует, и оставим только одно (последнее)
# Найдём все строки с "def _load_keys"
method_indices = []
for i, line in enumerate(new_lines):
    if 'def _load_keys(self):' in line:
        method_indices.append(i)

# Если больше одного определения, оставляем только последнее
if len(method_indices) > 1:
    # Удаляем все, кроме последнего
    for idx in reversed(method_indices[:-1]):
        # Удаляем строку с def и всё тело метода до следующего def или конца класса
        # Просто удалим от начала метода до следующего метода (или до конца)
        start = idx
        # Ищем конец метода (следующий def, не вложенный)
        end = None
        for j in range(idx+1, len(new_lines)):
            if re.match(r'^\s*def ', new_lines[j]):
                end = j
                break
        if end is None:
            end = len(new_lines)
        # Удаляем строки от start до end-1
        del new_lines[start:end]
    print("Удалены дублирующиеся определения _load_keys")

# Если нет определения метода, добавляем его
has_method = any('def _load_keys(self):' in line for line in new_lines)
if not has_method:
    print("Метод _load_keys не найден, добавляем...")
    # Найдём место для вставки (после closeEvent или buy_pro)
    insert_index = None
    for i in range(len(new_lines)-1, -1, -1):
        if 'def closeEvent' in new_lines[i] or 'def buy_pro' in new_lines[i]:
            insert_index = i
            break
    if insert_index is None:
        for i in range(len(new_lines)-1, -1, -1):
            if 'def ' in new_lines[i] and 'self' in new_lines[i]:
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
            f'{indent}        print(f"[ERROR] _load_keys: {{e}}")\n',
        ]
        new_lines = new_lines[:insert_index+1] + method_lines + new_lines[insert_index+1:]
        print("Метод _load_keys добавлен")

with open(filename, 'w') as f:
    f.writelines(new_lines)

print("✅ Очистка завершена. Пересобирайте приложение.")
