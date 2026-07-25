import sys
import re

filename = "main_window.py"
with open(filename, 'r') as f:
    lines = f.readlines()

# Проверяем, есть ли методы
has_buy_pro = any('def buy_pro' in line for line in lines)
has_defi = any('def _defi_payment_dialog' in line for line in lines)
has_check = any('def _check_payment' in line for line in lines)

if has_buy_pro and has_defi and has_check:
    print("Методы уже есть, пропускаем")
    sys.exit(0)

# Удаляем старые методы (если есть)
new_lines = []
skip = False
for line in lines:
    if 'def buy_pro' in line or 'def _defi_payment_dialog' in line or 'def _check_payment' in line:
        skip = True
        continue
    if skip and line.strip() and line.startswith('    ') and not line.strip().startswith('def'):
        continue
    if skip and (not line.startswith(' ') or line.strip().startswith('def')):
        skip = False
    if not skip:
        new_lines.append(line)

# Находим место для вставки (перед def run)
insert_index = None
for i, line in enumerate(new_lines):
    if line.strip().startswith('def run()'):
        insert_index = i
        break

if insert_index is None:
    print("Не найдена def run()")
    sys.exit(1)

# Создаём методы
methods = [
    '',
    '    def buy_pro(self):',
    '        dialog = QDialog(self)',
    '        dialog.setWindowTitle("Payment")',
    '        dialog.setMinimumWidth(400)',
    '        layout = QVBoxLayout(dialog)',
    '',
    '        label = QLabel("Select payment method:")',
    '        layout.addWidget(label)',
    '',
    '        self.check_defi = QCheckBox("DeFi (USDT/Solana) - for international payments")',
    '        self.check_website = QCheckBox("Website - for card payments")',
    '        layout.addWidget(self.check_defi)',
    '        layout.addWidget(self.check_website)',
    '',
    '        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)',
    '        btn_box.accepted.connect(dialog.accept)',
    '        btn_box.rejected.connect(dialog.reject)',
    '        layout.addWidget(btn_box)',
    '',
    '        if dialog.exec_() == QDialog.Accepted:',
    '            if self.check_defi.isChecked():',
    '                self._defi_payment_dialog()',
    '            elif self.check_website.isChecked():',
    '                import webbrowser',
    '                webbrowser.open("https://your-site.com/checkout")',
    '            else:',
    '                QMessageBox.warning(self, "Warning", "Please select a payment method.")',
    '',
    '    def _defi_payment_dialog(self):',
    '        try:',
    '            import requests',
    '            resp = requests.get(f"{self.api_url}/api/payment/defi/info", timeout=60)',
    '            if resp.status_code != 200:',
    '                QMessageBox.warning(self, "Error", "Failed to get payment info.")',
    '                return',
    '            data = resp.json()',
    '            msg = f"""',
    '            Pay {data["amount"]} {data["token"]} to wallet:',
    '',
    '            Network: {data["network"]}',
    '            Address: {data["wallet"]}',
    '            Memo: {data["memo"]}',
    '',
    '            After payment, click "Check payment".',
    '            """',
    '            reply = QMessageBox.question(',
    '                self, "DeFi Payment",',
    '                msg,',
    '                QMessageBox.Yes | QMessageBox.No,',
    '                QMessageBox.Yes',
    '            )',
    '            if reply == QMessageBox.Yes:',
    '                from PyQt5.QtWidgets import QApplication',
    '                clipboard = QApplication.clipboard()',
    '                clipboard.setText(data["wallet"])',
    '                QMessageBox.information(self, "Address copied", "Wallet address copied to clipboard.")',
    '                self._check_payment()',
    '        except Exception as e:',
    '            QMessageBox.critical(self, "Error", f"Error: {e}")',
    '',
    '    def _check_payment(self):',
    '        try:',
    '            import requests',
    '            resp = requests.post(f"{self.api_url}/api/payment/defi/check", timeout=60)',
    '            if resp.status_code == 200:',
    '                data = resp.json()',
    '                if data.get("success"):',
    '                    self.license_valid["premium"] = True',
    '                    self.settings["premium_key"] = "PAID-VIA-DEFI"',
    '                    save_settings(self.settings)',
    '                    self.update_usage_status()',
    '                    QMessageBox.information(self, "Success!", data.get("message", "License activated!"))',
    '                else:',
    '                    QMessageBox.warning(self, "Payment not found", data.get("message", "Try again in a minute."))',
    '            else:',
    '                QMessageBox.warning(self, "Error", "Failed to check payment.")',
    '        except Exception as e:',
    '            QMessageBox.critical(self, "Error", f"Check error: {e}")',
    '',
]

# Вставляем методы
new_lines = new_lines[:insert_index] + methods + new_lines[insert_index:]

with open(filename, 'w') as f:
    f.write('\n'.join(new_lines))

print("Методы оплаты добавлены")
