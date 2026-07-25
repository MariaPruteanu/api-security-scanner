import sys
import re

filename = "main_window.py"
with open(filename, 'r') as f:
    content = f.read()

# Добавляем метод для ручного ввода ключа
new_method = '''

    def enter_license_key(self):
        """Открывает диалог для ручного ввода лицензионного ключа."""
        key, ok = QInputDialog.getText(
            self, "Enter License Key",
            "Paste your license key:",
            QLineEdit.Password
        )
        if ok and key:
            # Пробуем определить тип ключа
            if key.startswith("PREMIUM-") and LicenseManager.validate_key(key, "premium"):
                self.license_valid["premium"] = True
                self.settings["premium_key"] = key
                save_settings(self.settings)
                self.update_usage_status()
                QMessageBox.information(self, "Success", "Premium license activated!")
            elif key.startswith("ENTERPRISE-") and LicenseManager.validate_key(key, "enterprise"):
                self.license_valid["enterprise"] = True
                self.settings["enterprise_key"] = key
                save_settings(self.settings)
                self.update_usage_status()
                QMessageBox.information(self, "Success", "Enterprise license activated!")
            else:
                QMessageBox.warning(self, "Error", "Invalid license key. Please check and try again.")
'''

# Вставляем метод перед def closeEvent
content = content.replace('def closeEvent(self, event):', new_method + '\n    def closeEvent(self, event):')

with open(filename, 'w') as f:
    f.write(content)

print("✅ Метод enter_license_key добавлен")
