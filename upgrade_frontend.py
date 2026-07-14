with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    ui = f.read()

# 1. Добавляем QDialog в импорты
if 'QDialog' not in ui:
    ui = ui.replace('from PyQt5.QtWidgets import (', 'from PyQt5.QtWidgets import (\n    QDialog,')

# 2. Класс диалога лицензии
license_dialog = '''
class LicenseDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Активация лицензии")
        self.setMinimumSize(400, 150)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Введите лицензионный ключ для Premium/Enterprise:"))
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("XXXX-XXXX-XXXX-XXXX")
        layout.addWidget(self.key_input)
        btn_layout = QHBoxLayout()
        ok_btn = QPushButton("Активировать")
        ok_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("Отмена")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(ok_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
    def get_key(self): return self.key_input.text().strip()

'''
if 'class LicenseDialog' not in ui:
    ui = ui.replace('class MainWindow(QMainWindow):', license_dialog + 'class MainWindow(QMainWindow):')

# 3. Подключаем проверку лицензии к выбору типа сканирования
if '_check_license' not in ui:
    ui = ui.replace(
        'self.type_combo.addItems(["Базовый", "Premium", "Enterprise"])',
        'self.type_combo.addItems(["Базовый", "Premium", "Enterprise"])\n        self.type_combo.currentTextChanged.connect(self._check_license)'
    )
    
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
                        try:
                            with open('license.key', 'w', encoding='utf-8') as f:
                                f.write(key)
                        except: pass
                        QMessageBox.information(self, "Успех", "Лицензия активирована!")
                    else: self.type_combo.setCurrentText("Базовый")
                else: self.type_combo.setCurrentText("Базовый")

'''
    ui = ui.replace('    def export_json', check_method + '    def export_json')

# 4. Словарь переводов
lang_dict = '''
UI_TEXTS = {
    'ru': {'title': '🛡️ API Security Scanner Pro v2.0', 'target': '🎯 Цель:', 'start': '🚀 Начать сканирование', 'mode': 'Режим:', 'type': 'Тип:', 'results': '📊 Результаты', 'log': '📝 Лог', 'how_to_fix': 'Как исправить', 'lang': 'Язык:'},
    'en': {'title': '🛡️ API Security Scanner Pro v2.0', 'target': '🎯 Target:', 'start': '🚀 Start Scan', 'mode': 'Mode:', 'type': 'Type:', 'results': '📊 Results', 'log': '📝 Log', 'how_to_fix': 'How to fix', 'lang': 'Language:'}
}

'''
if 'UI_TEXTS' not in ui:
    ui = ui.replace('class MainWindow(QMainWindow):', lang_dict + 'class MainWindow(QMainWindow):')

# 5. Переключатель языка
if 'self.lang_combo' not in ui:
    ui = ui.replace(
        'settings_layout.addWidget(self.type_combo)',
        'settings_layout.addWidget(self.type_combo)\n        settings_layout.addWidget(QLabel("Язык:"))\n        self.lang_combo = QComboBox()\n        self.lang_combo.addItems(["Русский", "English"])\n        self.lang_combo.currentTextChanged.connect(self._change_language)\n        settings_layout.addWidget(self.lang_combo)'
    )
    
    change_lang_method = '''
    def _change_language(self, lang_name):
        lang = 'ru' if lang_name == "Русский" else 'en'
        texts = UI_TEXTS.get(lang, UI_TEXTS['ru'])
        self.setWindowTitle(texts['title'])
        self.results_table.setHorizontalHeaderLabels(["ID", "Критичность", "Описание", texts['how_to_fix']])

'''
    ui = ui.replace('    def export_json', change_lang_method + '    def export_json')

# 6. Колонка "Как исправить" в таблице
ui = ui.replace('self.results_table.setColumnCount(3)', 'self.results_table.setColumnCount(4)')
ui = ui.replace(
    'self.results_table.setHorizontalHeaderLabels(["ID", "Критичность", "Описание"])',
    'self.results_table.setHorizontalHeaderLabels(["ID", "Критичность", "Описание", "Как исправить"])'
)

if 'row, 3, QTableWidgetItem' not in ui:
    ui = ui.replace(
        "self.results_table.setItem(row, 2, QTableWidgetItem(item.get('description', '')))",
        "self.results_table.setItem(row, 2, QTableWidgetItem(item.get('description', '')))\n            self.results_table.setItem(row, 3, QTableWidgetItem(item.get('remediation', '')))"
    )

with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
    f.write(ui)
print("✅ Frontend обновлён: Лицензия, перевод и колонка 'Как исправить' добавлены.")
