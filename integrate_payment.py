with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Добавляем импорт PurchaseDialog
if 'from purchase_dialog import' not in content:
    content = content.replace(
        'from PyQt5.QtGui import QFont',
        'from PyQt5.QtGui import QFont\nfrom purchase_dialog import PurchaseDialog'
    )

# Добавляем кнопку Upgrade рядом с типом сканирования
if 'upgrade_btn' not in content:
    old_type_combo = '''        self.type_combo = QComboBox()
        self.type_combo.addItems(["Базовый", "Premium", "Enterprise"])
        self.type_combo.currentTextChanged.connect(self._check_license)
        s_layout.addWidget(self.type_combo)'''
    
    new_type_combo = '''        self.type_combo = QComboBox()
        self.type_combo.addItems(["Базовый", "Premium", "Enterprise"])
        self.type_combo.currentTextChanged.connect(self._check_license)
        s_layout.addWidget(self.type_combo)
        
        self.upgrade_btn = QPushButton("💎 Upgrade")
        self.upgrade_btn.setStyleSheet("background-color: #e94560;")
        self.upgrade_btn.clicked.connect(self._open_purchase_dialog)
        s_layout.addWidget(self.upgrade_btn)'''
    
    content = content.replace(old_type_combo, new_type_combo)

# Добавляем метод открытия диалога покупки
if '_open_purchase_dialog' not in content:
    purchase_method = '''
    def _open_purchase_dialog(self):
        """Открывает диалог покупки лицензии"""
        dialog = PurchaseDialog(self)
        if dialog.exec_() == PurchaseDialog.Accepted:
            # Лицензия активирована, обновляем интерфейс
            QMessageBox.information(self, "✅ Success", "License activated! You can now use Premium/Enterprise features.")
            self.settings['license_key'] = open('license.key', 'r').read().strip()
            save_settings(self.settings)

'''
    content = content.replace('    def _check_license', purchase_method + '    def _check_license')

with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("✅ Payment интегрирован в main_window.py!")
