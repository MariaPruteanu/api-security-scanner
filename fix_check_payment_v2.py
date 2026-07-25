import sys
import re

filename = "main_window.py"
with open(filename, 'r') as f:
    content = f.read()

# Находим метод _check_payment и добавляем активацию и показ ключа
pattern = r'(def _check_payment\(self\):.*?if data\.get\("success"\):.*?self\.license_valid\["premium"\] = True.*?QMessageBox\.information\(self, "Success!", data\.get\("message", "License activated!"\)\))'
replacement = r'''\1
                    # Генерируем ключ для пользователя
                    import secrets
                    import string
                    key_prefix = "PREMIUM" if self.scan_type_combo.currentIndex() == 1 else "ENTERPRISE"
                    random_part = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(12))
                    new_key = f"{key_prefix}-{random_part}"
                    self.license_valid["premium"] = True
                    self.settings["premium_key"] = new_key
                    save_settings(self.settings)
                    self.update_usage_status()
                    QMessageBox.information(
                        self, "License Activated!",
                        f"Your {key_prefix} license key:\n\n{new_key}\n\n"
                        "This key has been saved. You can also find it in Settings."
                    )'''

content = re.sub(pattern, replacement, content, flags=re.DOTALL)

with open(filename, 'w') as f:
    f.write(content)

print("✅ _check_payment обновлён — добавлена генерация ключа")
