import sys
import re

filename = "main_window.py"
with open(filename, 'r') as f:
    content = f.read()

# Находим место, где активируется лицензия, и добавляем save_settings
pattern = r'(self\.license_valid\[scan_type\] = True\n\s+self\.settings\[f"{scan_type}_key"\] = key)'
replacement = r'''\1
                    save_settings(self.settings)
                    print(f"[DEBUG] {scan_type.capitalize()} ключ сохранён в настройках")'''

content = re.sub(pattern, replacement, content, flags=re.DOTALL)

with open(filename, 'w') as f:
    f.write(content)
print("✅ Сохранение ключей добавлено")
