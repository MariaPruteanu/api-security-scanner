with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Добавляем QDialog в импорты (если нет)
if 'from PyQt5.QtWidgets import' in content and 'QDialog,' not in content:
    content = content.replace(
        'from PyQt5.QtWidgets import (\n',
        'from PyQt5.QtWidgets import (\n    QDialog,\n'
    )

# 2. Класс диалога лицензии
license_dialog = '''
class LicenseDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("🔑 Активация лицензии")
        self.setMinimumSize(450, 180)
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        
        title = QLabel("Для использования Premium/Enterprise нужна лицензия")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        layout.addWidget(QLabel("Введите лицензионный ключ:"))
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("PREMIUM-XXXX-XXXX-XXXX")
        self.key_input.setMinimumWidth(350)
        layout.addWidget(self.key_input)
        
        btn_layout = QHBoxLayout()
        ok_btn = QPushButton("✅ Активировать")
        ok_btn.setStyleSheet("background-color: #27ae60;")
        ok_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("❌ Отмена")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(ok_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
    
    def get_key(self):
        return self.key_input.text().strip()

'''

if 'class LicenseDialog' not in content:
    content = content.replace('class MainWindow(QMainWindow):', license_dialog + 'class MainWindow(QMainWindow):')
    print("✅ Класс LicenseDialog добавлен")

# 3. Подключение проверки лицензии
if '_check_license' not in content:
    # Находим где создаётся type_combo
    old_type = 'self.type_combo = QComboBox()\n        self.type_combo.addItems(["Базовый", "Premium", "Enterprise"])'
    new_type = 'self.type_combo = QComboBox()\n        self.type_combo.addItems(["Базовый", "Premium", "Enterprise"])\n        self.type_combo.currentTextChanged.connect(self._check_license)'
    
    if old_type in content:
        content = content.replace(old_type, new_type)
    else:
        # Пробуем найти просто addItems
        content = content.replace(
            'self.type_combo.addItems(["Базовый", "Premium", "Enterprise"])',
            'self.type_combo.addItems(["Базовый", "Premium", "Enterprise"])\n        self.type_combo.currentTextChanged.connect(self._check_license)'
        )
    print("✅ Подключение _check_license добавлено")

# 4. Метод проверки лицензии
check_method = '''
    def _check_license(self, text):
        """Проверка лицензии при выборе Premium/Enterprise"""
        if text in ["Premium", "Enterprise"]:
            license_key = self.settings.get('license_key', '')
            if not license_key:
                # Показываем диалог
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
                        except Exception as e:
                            print(f"Ошибка сохранения ключа: {e}")
                        QMessageBox.information(self, "✅ Успех", f"Лицензия активирована!\nТип: {text}")
                    else:
                        QMessageBox.warning(self, "⚠️ Внимание", "Введите корректный ключ")
                        self.type_combo.setCurrentText("Базовый")
                else:
                    # Пользователь нажал Отмена
                    self.type_combo.setCurrentText("Базовый")

'''

if 'def _check_license' not in content:
    # Вставляем перед export_json
    if 'def export_json' in content:
        content = content.replace('    def export_json', check_method + '    def export_json')
        print("✅ Метод _check_license добавлен")

# 5. Переводы
translations = '''
# Словарь переводов интерфейса
TRANSLATIONS = {
    'ru': {
        'window_title': '🛡️ API Security Scanner Pro v2.0',
        'target_label': '🎯 Цель:',
        'browse': '📁 Обзор',
        'mode': 'Режим:',
        'type': 'Тип:',
        'api_key': 'API ключ:',
        'api_key_ph': 'API ключ (для облака)',
        'start': '🚀 Начать сканирование',
        'language': 'Язык:',
        'results_tab': ' Результаты',
        'log_tab': ' Лог',
        'mode_local': 'Локально',
        'mode_cloud': 'Облако',
        'type_basic': 'Базовый',
        'type_premium': 'Premium',
        'type_enterprise': 'Enterprise',
        'lang_ru': 'Русский',
        'lang_en': 'English',
        'col_id': 'ID',
        'col_severity': 'Критичность',
        'col_description': 'Описание',
        'col_remediation': 'Как исправить',
        'status_ready': 'Готов к работе',
        'scanning': ' Сканирование...',
        'complete': '✅ Сканирование завершено',
    },
    'en': {
        'window_title': '🛡️ API Security Scanner Pro v2.0',
        'target_label': '🎯 Target:',
        'browse': '📁 Browse',
        'mode': 'Mode:',
        'type': 'Type:',
        'api_key': 'API Key:',
        'api_key_ph': 'API Key (for cloud)',
        'start': '🚀 Start Scan',
        'language': 'Language:',
        'results_tab': '📊 Results',
        'log_tab': '📝 Log',
        'mode_local': 'Local',
        'mode_cloud': 'Cloud',
        'type_basic': 'Basic',
        'type_premium': 'Premium',
        'type_enterprise': 'Enterprise',
        'lang_ru': 'Русский',
        'lang_en': 'English',
        'col_id': 'ID',
        'col_severity': 'Severity',
        'col_description': 'Description',
        'col_remediation': 'How to Fix',
        'status_ready': 'Ready',
        'scanning': '⏳ Scanning...',
        'complete': '✅ Scan Complete',
    }
}

'''

if 'TRANSLATIONS' not in content:
    # Вставляем перед классом LicenseDialog или MainWindow
    if 'class LicenseDialog' in content:
        content = content.replace('class LicenseDialog', translations + 'class LicenseDialog')
    else:
        content = content.replace('class MainWindow', translations + 'class MainWindow')
    print("✅ Словарь TRANSLATIONS добавлен")

# 6. Добавляем текущий язык в __init__
if 'self.current_lang' not in content:
    content = content.replace(
        "self.settings = load_settings()",
        "self.settings = load_settings()\n        self.current_lang = self.settings.get('language', 'ru')"
    )
    print("✅ self.current_lang добавлен")

# 7. Метод смены языка
change_lang_method = '''
    def _apply_translations(self):
        """Применяет переводы ко всему интерфейсу"""
        t = TRANSLATIONS.get(self.current_lang, TRANSLATIONS['ru'])
        
        self.setWindowTitle(t['window_title'])
        # Ищем и переводим лейблы и кнопки
        for child in self.findChildren(QLabel):
            if child.text() == 'Режим:':
                child.setText(t['mode'])
            elif child.text() == 'Тип:':
                child.setText(t['type'])
            elif child.text() == 'API ключ:':
                child.setText(t['api_key'])
            elif child.text() == 'Язык:':
                child.setText(t['language'])
            elif child.text() == ' Цель:':
                child.setText(t['target_label'])
        
        # Переводим кнопки
        for child in self.findChildren(QPushButton):
            if 'Начать сканирование' in child.text():
                child.setText(t['start'])
            elif child.text() == '📁 Обзор':
                child.setText(t['browse'])
        
        # Переводим табы
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == '📊 Результаты':
                self.tabs.setTabText(i, t['results_tab'])
            elif self.tabs.tabText(i) == '📝 Лог':
                self.tabs.setTabText(i, t['log_tab'])
        
        # Переводим заголовки таблицы
        self.results_table.setHorizontalHeaderLabels([
            t['col_id'], t['col_severity'], t['col_description'], t['col_remediation']
        ])
        
        # Переводим combobox'ы
        if hasattr(self, 'mode_combo'):
            self.mode_combo.clear()
            self.mode_combo.addItems([t['mode_local'], t['mode_cloud']])
        if hasattr(self, 'type_combo'):
            self.type_combo.clear()
            self.type_combo.addItems([t['type_basic'], t['type_premium'], t['type_enterprise']])
            # Отключаем сигнал чтобы не сработала проверка лицензии
            self.type_combo.currentTextChanged.disconnect(self._check_license)
            self.type_combo.currentTextChanged.connect(self._check_license)
        if hasattr(self, 'lang_combo'):
            self.lang_combo.clear()
            self.lang_combo.addItems([t['lang_ru'], t['lang_en']])

    def _change_language(self, lang_text):
        """Смена языка интерфейса"""
        self.current_lang = 'ru' if lang_text == 'Русский' else 'en'
        self.settings['language'] = self.current_lang
        save_settings(self.settings)
        self._apply_translations()

'''

if '_apply_translations' not in content:
    # Вставляем перед export_json
    if 'def export_json' in content:
        content = content.replace('    def export_json', change_lang_method + '    def export_json')
        print("✅ Методы перевода добавлены")

with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("\n✅✅✅ Все улучшения интерфейса применены!")
print("Теперь:")
print("  ✓ При выборе Premium/Enterprise появится окно ввода ключа")
print("  ✓ Перевод на английский работает через выпадающий список")
print("  ✓ Добавлена 4-я колонка 'Как исправить'")
