import sys
import re

filename = "main_window.py"
with open(filename, 'r') as f:
    content = f.read()

# Находим метод _check_payment и добавляем запрос tx_hash
pattern = r'(def _check_payment\(self\):.*?resp = requests\.post\(f"{self\.api_url}/api/payment/defi/check", timeout=60\))'
replacement = r'''\1
            # Запрашиваем у пользователя tx_hash
            tx_hash, ok = QInputDialog.getText(
                self, "Transaction Hash",
                "Enter the transaction hash from Solana explorer:",
                QLineEdit.Normal
            )
            if not ok or not tx_hash:
                QMessageBox.warning(self, "Warning", "Transaction hash is required.")
                return
            resp = requests.post(
                f"{self.api_url}/api/payment/defi/check",
                params={"tx_hash": tx_hash},
                timeout=60
            )'''

content = re.sub(pattern, replacement, content, flags=re.DOTALL)

with open(filename, 'w') as f:
    f.write(content)

print("✅ _check_payment обновлён")
