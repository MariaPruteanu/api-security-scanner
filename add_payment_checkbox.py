import sys
import re

filename = "main_window.py"
with open(filename, 'r') as f:
    content = f.read()

# Находим метод buy_pro и заменяем его
new_buy_pro = '''
    def buy_pro(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Payment")
        dialog.setMinimumWidth(400)
        layout = QVBoxLayout(dialog)
        
        label = QLabel("Select payment method:")
        layout.addWidget(label)
        
        self.check_defi = QCheckBox("DeFi (USDT/Solana) - for international payments")
        self.check_website = QCheckBox("Website - for card payments")
        layout.addWidget(self.check_defi)
        layout.addWidget(self.check_website)
        
        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.accepted.connect(dialog.accept)
        btn_box.rejected.connect(dialog.reject)
        layout.addWidget(btn_box)
        
        if dialog.exec_() == QDialog.Accepted:
            if self.check_defi.isChecked():
                self._defi_payment_dialog()
            elif self.check_website.isChecked():
                import webbrowser
                webbrowser.open("https://your-site.com/checkout")
            else:
                QMessageBox.warning(self, "Warning", "Please select a payment method.")
'''

# Заменяем старый метод
pattern = r'def buy_pro\(self\):.*?(?=def _defi_payment_dialog)'
content = re.sub(pattern, new_buy_pro, content, flags=re.DOTALL)

with open(filename, 'w') as f:
    f.write(content)

print("✅ Payment dialog updated with checkboxes")
