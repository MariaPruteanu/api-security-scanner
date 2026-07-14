with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Обновляем класс LicenseDialog чтобы он принимал тип лицензии
old_dialog = '''class LicenseDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(" Активация лицензии")
        self.setMinimumSize(450, 180)
        self.setModal(True)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Для использования Premium/Enterprise нужна лицензия.\\nВведите ключ:"))
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("PREMIUM-XXXX-XXXX-XXXX")
        layout.addWidget(self.key_input)
        btns = QHBoxLayout()
        ok = QPushButton("✅ Активировать"); ok.clicked.connect(self.accept)
        cancel = QPushButton("❌ Отмена"); cancel.clicked.connect(self.reject)
        btns.addWidget(ok); btns.addWidget(cancel)
        layout.addLayout(btns)
    def get_key(self): return self.key_input.text().strip()'''

new_dialog = '''class LicenseDialog(QDialog):
    def __init__(self, license_type: str = "Premium", parent=None):
        super().__init__(parent)
        self.license_type = license_type
        
        # Разные настройки для Premium и Enterprise
        if license_type == "Enterprise":
            self.setWindowTitle("🚀 Активация Enterprise лицензии")
            title = "🚀 Активация Enterprise версии"
            desc = "Для использования всех функций Enterprise нужна лицензия.\\n\\nВключает:\\n✓ Все 49+ правил безопасности\\n✓ Менеджер правил\\n✓ Экспорт в PDF/JSON\\n✓ Приоритетная поддержка\\n✓ Кастомные правила\\n\\nВведите лицензионный ключ:"
            placeholder = "ENT-XXXX-XXXX-XXXX-XXXX"
            color = "#9b59b6"  # Purple for Enterprise
        else:  # Premium
            self.setWindowTitle("⭐ Активация Premium лицензии")
            title = "⭐ Активация Premium версии"
            desc = "Для использования Premium функций нужна лицензия.\\n\\nВключает:\\n✓ Все 49 правил безопасности\\n✓ Менеджер правил\\n✓ Расширенные отчёты\\n\\nВведите лицензионный ключ:"
            placeholder = "PREMIUM-XXXX-XXXX-XXXX"
            color = "#f39c12"  # Orange for Premium
        
        self.setMinimumSize(500, 280 if license_type == "Enterprise" else 250)
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        
        # Заголовок
        title_label = QLabel(title)
        title_label.setFont(QFont("Arial", 14, QFont.Bold))
        title_label.setStyleSheet(f"color: {color};")
        layout.addWidget(title_label)
        
        # Описание
        desc_label = QLabel(desc)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("color: #e0e0e0; padding: 10px;")
        layout.addWidget(desc_label)
        
        # Поле ввода
        layout.addWidget(QLabel("🔑 Лицензионный ключ:"))
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText(placeholder)
        self.key_input.setMinimumWidth(350)
        self.key_input.setStyleSheet("font-family: monospace; font-size: 13px; padding: 5px;")
        layout.addWidget(self.key_input)
        
        # Кнопки
        btns = QHBoxLayout()
        ok = QPushButton(f"✅ Активировать {license_type}")
        ok.setStyleSheet(f"background-color: {color}; font-weight: bold; padding: 8px 20px;")
        ok.clicked.connect(self.accept)
        cancel = QPushButton("❌ Отмена")
        cancel.clicked.connect(self.reject)
        btns.addWidget(ok); btns.addWidget(cancel)
        layout.addLayout(btns)
    
    def get_key(self): 
        return self.key_input.text().strip()'''

if old_dialog in content:
    content = content.replace(old_dialog, new_dialog)
    print("✅ LicenseDialog обновлён с разными окнами для Premium/Enterprise")
else:
    print("⚠️ Не удалось найти старый диалог. Возможно, он уже изменён.")

# 2. Обновляем метод _check_license чтобы он передавал тип лицензии
old_check = '''    def _check_license(self, text):
        if text in ["Premium", "Enterprise"] and not self.settings.get('license_key'):
            dialog = LicenseDialog(self)'''

new_check = '''    def _check_license(self, text):
        if text in ["Premium", "Enterprise"] and not self.settings.get('license_key'):
            dialog = LicenseDialog(license_type=text, parent=self)'''

if old_check in content:
    content = content.replace(old_check, new_check)
    print("✅ Метод _check_license обновлён для передачи типа лицензии")
else:
    print("️ Не удалось найти _check_license")

with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("\\n✅✅✅ Диалоги лицензий разделены!")
print("  ✓ Premium: оранжевое окно с 3 преимуществами")
print("  ✓ Enterprise: фиолетовое окно с 5 преимуществами")
