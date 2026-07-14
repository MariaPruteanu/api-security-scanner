with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Добавляем QDialog в импорты, если его нет
if 'QDialog' not in content:
    content = content.replace(
        'from PyQt5.QtWidgets import (',
        'from PyQt5.QtWidgets import (\n    QDialog,'
    )

# 2. Добавляем класс диалога перед MainWindow
dialog_class = '''
class LicenseDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Активация лицензии")
        self.setMinimumSize(400, 150)
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Введите лицензионный ключ:"))
        
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("XXXX-XXXX-XXXX-XXXX")
        self.key_input.setMinimumWidth(300)
        layout.addWidget(self.key_input)
        
        btn_layout = QHBoxLayout()
        ok_btn = QPushButton("Активировать")
        ok_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("Отмена")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(ok_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
    
    def get_key(self):
        return self.key_input.text().strip()

'''

if 'class LicenseDialog' not in content:
    content = content.replace('class MainWindow(QMainWindow):', dialog_class + 'class MainWindow(QMainWindow):')

# 3. Добавляем реакцию на смену типа сканирования
old_combo = 'self.type_combo = QComboBox()\n        self.type_combo.addItems(["Базовый", "Premium", "Enterprise"])'
new_combo = '''self.type_combo = QComboBox()
        self.type_combo.addItems(["Базовый", "Premium", "Enterprise"])
        self.type_combo.currentTextChanged.connect(self._check_license)'''

content = content.replace(old_combo, new_combo)

# 4. Добавляем метод проверки
check_method = '''
    def _check_license(self, text):
        if text in ["Premium", "Enterprise"]:
            if not self.settings.get('license_key'):
                dialog = LicenseDialog(self)
                if dialog.exec_() == QDialog.Accepted:
                    key = dialog.get_key()
                    if key:
                        self.settings['license_key'] = key
                        save_settings(self.settings)
                        # Сохраняем в файл
                        try:
                            with open('license.key', 'w', encoding='utf-8') as f:
                                f.write(key)
                        except Exception:
                            pass
                        QMessageBox.information(self, "Успех", "Лицензия активирована!")
                    else:
                        self.type_combo.setCurrentText("Базовый")
                else:
                    self.type_combo.setCurrentText("Базовый")

'''

if 'def _check_license' not in content:
    content = content.replace('    def export_json', check_method + '    def export_json')

with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("✅ Диалог ввода лицензии добавлен!")
