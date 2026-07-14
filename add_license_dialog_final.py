with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Добавляем QDialog в импорты
if 'QDialog' not in content and 'from PyQt5.QtWidgets import' in content:
    content = content.replace(
        'from PyQt5.QtWidgets import (',
        'from PyQt5.QtWidgets import (\n    QDialog,'
    )

# 2. Добавляем класс диалога
dialog_class = '''
class LicenseDialog(QDialog):
    """Диалог ввода лицензионного ключа для Premium/Enterprise"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Активация лицензии")
        self.setMinimumSize(450, 180)
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        
        label = QLabel("Введите лицензионный ключ для Premium/Enterprise:")
        label.setStyleSheet("font-size: 14px; margin-bottom: 10px;")
        layout.addWidget(label)
        
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("XXXX-XXXX-XXXX-XXXX")
        self.key_input.setMinimumWidth(350)
        self.key_input.setStyleSheet("font-size: 14px; padding: 8px;")
        layout.addWidget(self.key_input)
        
        btn_layout = QHBoxLayout()
        ok_btn = QPushButton("Активировать")
        ok_btn.setStyleSheet("background-color: #27ae60; color: white; padding: 10px;")
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

# 3. Добавляем обработку смены типа сканирования
old_combo = '''self.type_combo = QComboBox()
        self.type_combo.addItems(["Базовый", "Premium", "Enterprise"])'''
new_combo = '''self.type_combo = QComboBox()
        self.type_combo.addItems(["Базовый", "Premium", "Enterprise"])
        self.type_combo.currentTextChanged.connect(self._on_type_changed)'''
content = content.replace(old_combo, new_combo)

# 4. Добавляем метод проверки лицензии
check_method = '''
    def _on_type_changed(self, text):
        """Проверка лицензии при выборе Premium/Enterprise"""
        if text in ["Premium", "Enterprise"]:
            license_key = self.settings.get('license_key', '')
            if not license_key:
                dialog = LicenseDialog(self)
                if dialog.exec_() == QDialog.Accepted:
                    key = dialog.get_key()
                    if key:
                        self.settings['license_key'] = key
                        save_settings(self.settings)
                        # Сохраняем в файл
                        license_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'license.key')
                        try:
                            with open(license_file, 'w', encoding='utf-8') as f:
                                f.write(key)
                        except Exception:
                            pass
                        QMessageBox.information(self, "Успех", "✅ Лицензия активирована!")
                    else:
                        self.type_combo.setCurrentText("Базовый")
                else:
                    self.type_combo.setCurrentText("Базовый")

'''

if 'def _on_type_changed' not in content:
    content = content.replace('    def export_json', check_method + '    def export_json')

with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("✅ Диалог ввода лицензии добавлен!")
