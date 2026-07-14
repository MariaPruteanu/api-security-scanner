import sys
import re
import os

filename = "main_window.py"
with open(filename, 'r') as f:
    lines = f.readlines()

# Найдём строку с apply_keys_from_files(self)
target_index = None
for i, line in enumerate(lines):
    if 'apply_keys_from_files(self)' in line and not line.strip().startswith('#'):
        target_index = i
        break

if target_index is None:
    print("Не найдена строка apply_keys_from_files(self)")
    sys.exit(1)

# Определим отступ текущей строки
indent = re.match(r'^(\s*)', lines[target_index]).group(1)

# Проверим, есть ли уже print перед этой строкой (чтобы не дублировать)
if target_index > 0 and 'print("[DEBUG] Перед вызовом' in lines[target_index - 1]:
    print("Отладочный print уже есть, пропускаем")
    sys.exit(0)

# Вставляем print перед строкой
insert_lines = [
    f'{indent}print("[DEBUG] Перед вызовом apply_keys_from_files")\n',
    f'{indent}print(f"[DEBUG] license_valid до вызова: {{self.license_valid}}")\n'
]
for insert in reversed(insert_lines):
    lines.insert(target_index, insert)

with open(filename, 'w') as f:
    f.writelines(lines)

print("✅ Отладка добавлена в main_window.py")
