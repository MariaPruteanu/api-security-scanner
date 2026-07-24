import sys
import re

filename = "main_window.py"
with open(filename, 'r') as f:
    content = f.read()

# Добавляем блок загрузки ключей из настроек в __init__
# Ищем место после self.settings = load_settings()
pattern = r'(self\.settings = load_settings\(\))'
replacement = r'''\1
        # Загружаем сохранённые ключи из настроек
        if self.settings.get('premium_key') and LicenseManager.validate_key(self.settings['premium_key'], 'premium'):
            self.license_valid['premium'] = True
            print("[DEBUG] Premium ключ загружен из настроек")
        if self.settings.get('enterprise_key') and LicenseManager.validate_key(self.settings['enterprise_key'], 'enterprise'):
            self.license_valid['enterprise'] = True
            print("[DEBUG] Enterprise ключ загружен из настроек")'''

content = re.sub(pattern, replacement, content, flags=re.DOTALL)

with open(filename, 'w') as f:
    f.write(content)
print("✅ Загрузка ключей из настроек добавлена")
