import re
import sys

filename = "main_window.py"
with open(filename, 'r') as f:
    lines = f.readlines()

# Найдём строку с is_enterprise
target_index = None
for i, line in enumerate(lines):
    if 'is_enterprise = self.license_valid.get("enterprise", False)' in line:
        target_index = i
        break

if target_index is None:
    print("Не найдена строка is_enterprise")
    sys.exit(1)

indent = re.match(r'^(\s*)', lines[target_index]).group(1)

# Вставляем print после этой строки
new_line = f'{indent}print(f"[DEBUG] В start_scan: is_premium={{is_premium}}, is_enterprise={{is_enterprise}}")\n'
lines.insert(target_index + 1, new_line)

with open(filename, 'w') as f:
    f.writelines(lines)

print("Отладка добавлена после is_enterprise")
