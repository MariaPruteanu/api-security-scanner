import re
import sys

filename = "main_window.py"
with open(filename, 'r') as f:
    lines = f.readlines()

# Найдём строку с is_premium = ...
target_line = None
target_index = None
for i, line in enumerate(lines):
    if 'is_premium = self.license_valid.get("premium", False)' in line:
        target_index = i
        break

if target_index is None:
    print("Не найдена строка is_premium")
    sys.exit(1)

# Определяем отступ
indent = re.match(r'^(\s*)', lines[target_index]).group(1)

# Проверяем, есть ли уже print с [DEBUG] В start_scan
for line in lines:
    if '[DEBUG] В start_scan' in line:
        print("Отладочный print уже существует, пропускаем")
        sys.exit(0)

# Вставляем print после строки
new_line = f'{indent}print(f"[DEBUG] В start_scan: is_premium={{is_premium}}, is_enterprise={{is_enterprise}}")\n'
lines.insert(target_index + 1, new_line)

with open(filename, 'w') as f:
    f.writelines(lines)

print("Отладка добавлена успешно")
