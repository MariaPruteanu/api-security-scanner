import sys
import re

filename = "main_window.py"
with open(filename, 'r') as f:
    content = f.read()

# Проверяем, есть ли уже методы
if 'def buy_pro' in content and 'def _defi_payment_dialog' in content and 'def _check_payment' in content:
    print("Методы уже есть, пропускаем")
    sys.exit(0)

# Ищем строку def run()
run_index = content.find('\ndef run():')
if run_index == -1:
    print("Не найдена def run()")
    sys.exit(1)

# Методы для вставки
methods = '''
    def buy_pro(self):
        """Открывает диалог с вариантами оплаты."""
        msg = """
Выберите способ оплаты:

1️⃣ DeFi (USDT/Solana) — для международных платежей
2️⃣ Сайт — для оплаты картой (РФ и зарубеж)
"""
        reply = QMessageBox.question(
            self, "Выберите способ оплаты",
            msg,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes
        )
        if reply == QMessageBox.Yes:
            self._defi_payment_dialog()
        else:
            import webbrowser
            webbrowser.open("https://your-site.com/checkout")

    def _defi_payment_dialog(self):
        """Показывает окно с информацией для оплаты через DeFi."""
        try:
            import requests
            resp = requests.get(f"{self.api_url}/api/payment/defi/info", timeout=30)
            if resp.status_code != 200:
                QMessageBox.warning(self, "Ошибка", "Не удалось получить информацию для оплаты.")
                return
            data = resp.json()
            msg = f"""
Оплатите {data['amount']} {data['token']} на кошелёк:

🌐 Сеть: {data['network']}
💰 Адрес: {data['wallet']}
📝 Memo: {data['memo']}

После оплаты нажмите «Проверить оплату».
"""
            reply = QMessageBox.question(
                self, "Оплата через DeFi",
                msg,
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            if reply == QMessageBox.Yes:
                from PyQt5.QtWidgets import QApplication
                clipboard = QApplication.clipboard()
                clipboard.setText(data['wallet'])
                QMessageBox.information(self, "Адрес скопирован", "Адрес кошелька скопирован в буфер обмена.")
                self._check_payment()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка: {e}")

    def _check_payment(self):
        """Проверяет, была ли оплата."""
        try:
            import requests
            resp = requests.post(f"{self.api_url}/api/payment/defi/check", timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('success'):
                    self.license_valid['premium'] = True
                    self.settings['premium_key'] = "PAID-VIA-DEFI"
                    save_settings(self.settings)
                    self.update_usage_status()
                    QMessageBox.information(self, "Успех!", data.get('message', 'Лицензия активирована!'))
                else:
                    QMessageBox.warning(self, "Оплата не найдена", data.get('message', 'Попробуйте ещё раз через минуту.'))
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось проверить оплату.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка проверки: {e}")
'''

# Вставляем методы перед def run()
new_content = content[:run_index] + methods + content[run_index:]

with open(filename, 'w') as f:
    f.write(new_content)

print("✅ Методы оплаты добавлены")
