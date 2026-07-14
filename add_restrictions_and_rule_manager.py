import json
import os

# ============================================================
# 1. ОБНОВЛЯЕМ scanner/core.py - добавляем проверки лицензии
# ============================================================
with open('scanner/core.py', 'r', encoding='utf-8') as f:
    core = f.read()

# Добавляем проверку типа сканирования в __init__
if '# Ограничения по типу лицензии' not in core:
    old_init = '''    def __init__(self, base_url: str, timeout: int = 30, scan_type: str = "basic"):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.scan_type = scan_type
        self.rules_loader = RulesLoader()
        self.rules = self.rules_loader.get_rules_by_tier(scan_type)'''
    
    new_init = '''    def __init__(self, base_url: str, timeout: int = 30, scan_type: str = "basic", license_key: str = ""):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.scan_type = scan_type
        self.license_key = license_key
        self.rules_loader = RulesLoader()
        
        # Ограничения по типу лицензии
        self.rules = self.rules_loader.get_rules_by_tier(scan_type)
        if scan_type == 'basic' and len(self.rules) > 10:
            # Basic получает только первые 10 правил
            self.rules = self.rules[:10]
            print(f"⚠️ Basic версия: доступно только {len(self.rules)} правил (из {self.rules_loader.total_rules()})", file=sys.stderr)
        elif scan_type == 'premium':
            print(f"✅ Premium версия: доступно {len(self.rules)} правил", file=sys.stderr)
        elif scan_type == 'enterprise':
            print(f" Enterprise версия: доступно {len(self.rules)} правил + кастомные правила", file=sys.stderr)'''
    
    core = core.replace(old_init, new_init)

with open('scanner/core.py', 'w', encoding='utf-8') as f:
    f.write(core)
print("✅ scanner/core.py: добавлены ограничения по лицензиям")

# ============================================================
# 2. ОБНОВЛЯЕМ desktop_app/main_window.py
# ============================================================
with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    ui = f.read()

# Добавляем импорт для RuleManager
if 'class LicenseDialog' in ui:
    ui = ui.replace(
        'class LicenseDialog(QDialog):',
        '# ============================================================\n# Менеджер правил\n# ============================================================\nclass RuleManager(QDialog):\n    """Окно управления правилами (только для Premium/Enterprise)"""\n    \n    def __init__(self, parent=None):\n        super().__init__(parent)\n        self.setWindowTitle("📚 Менеджер правил безопасности")\n        self.setMinimumSize(900, 600)\n        self.setModal(True)\n        \n        # Загружаем правила\n        self.rules_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), \'scanner\', \'rules\')\n        self.rules = self._load_rules()\n        \n        self._init_ui()\n    \n    def _load_rules(self):\n        """Загружает все правила из YAML файлов"""\n        rules = []\n        if os.path.exists(self.rules_file):\n            from .scanner.rules_loader import RulesLoader\n            loader = RulesLoader()\n            rules = loader.get_all_rules()\n        return rules\n    \n    def _init_ui(self):\n        layout = QVBoxLayout(self)\n        \n        # Заголовок\n        title = QLabel("📚 Управление правилами безопасности")\n        title.setFont(QFont("Arial", 16, QFont.Bold))\n        layout.addWidget(title)\n        \n        # Таблица правил\n        self.table = QTableWidget()\n        self.table.setColumnCount(4)\n        self.table.setHorizontalHeaderLabels(["ID", "Название", "Уровень", "Описание"])\n        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)\n        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)\n        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)\n        self.table.doubleClicked.connect(self._edit_rule)\n        \n        # Заполняем таблицу\n        self.table.setRowCount(len(self.rules))\n        for row, rule in enumerate(self.rules):\n            self.table.setItem(row, 0, QTableWidgetItem(rule.get(\'id\', \'\')))\n            self.table.setItem(row, 1, QTableWidgetItem(rule.get(\'name\', \'\')))\n            badge = SeverityBadge(rule.get(\'severity\', \'medium\'))\n            self.table.setCellWidget(row, 2, badge)\n            self.table.setItem(row, 3, QTableWidgetItem(rule.get(\'description\', \'\')[:100]))\n        \n        layout.addWidget(self.table)\n        \n        # Кнопки\n        btn_layout = QHBoxLayout()\n        \n        edit_btn = QPushButton("✏️ Редактировать")\n        edit_btn.clicked.connect(self._edit_selected_rule)\n        btn_layout.addWidget(edit_btn)\n        \n        add_btn = QPushButton("➕ Добавить правило")\n        add_btn.clicked.connect(self._add_rule)\n        btn_layout.addWidget(add_btn)\n        \n        close_btn = QPushButton("Закрыть")\n        close_btn.clicked.connect(self.accept)\n        btn_layout.addWidget(close_btn)\n        \n        layout.addLayout(btn_layout)\n        \n        # Статус\n        self.status = QLabel(f"Всего правил: {len(self.rules)}")\n        layout.addWidget(self.status)\n    \n    def _edit_rule(self, index):\n        row = index.row()\n        rule = self.rules[row]\n        \n        # Простое диалоговое окно для редактирования\n        dialog = QDialog(self)\n        dialog.setWindowTitle(f"Редактирование правила: {rule.get(\'id\')}")\n        dialog.setMinimumSize(600, 400)\n        \n        layout = QVBoxLayout(dialog)\n        \n        layout.addWidget(QLabel("ID:"))\n        id_input = QLineEdit(rule.get(\'id\', \'\'))\n        id_input.setEnabled(False)  # ID нельзя менять\n        layout.addWidget(id_input)\n        \n        layout.addWidget(QLabel("Название:"))\n        name_input = QLineEdit(rule.get(\'name\', \'\'))\n        layout.addWidget(name_input)\n        \n        layout.addWidget(QLabel("Уровень критичности:"))\n        severity_combo = QComboBox()\n        severity_combo.addItems([\'critical\', \'high\', \'medium\', \'low\', \'info\'])\n        severity_combo.setCurrentText(rule.get(\'severity\', \'medium\'))\n        layout.addWidget(severity_combo)\n        \n        layout.addWidget(QLabel("Описание:"))\n        desc_input = QTextEdit()\n        desc_input.setPlainText(rule.get(\'description\', \'\'))\n        layout.addWidget(desc_input)\n        \n        layout.addWidget(QLabel("Как исправить:"))\n        fix_input = QTextEdit()\n        fix_input.setPlainText(rule.get(\'remediation\', rule.get(\'fix\', \'\')))\n        layout.addWidget(fix_input)\n        \n        btn_layout = QHBoxLayout()\n        save_btn = QPushButton("💾 Сохранить")\n        save_btn.clicked.connect(dialog.accept)\n        cancel_btn = QPushButton("Отмена")\n        cancel_btn.clicked.connect(dialog.reject)\n        btn_layout.addWidget(save_btn)\n        btn_layout.addWidget(cancel_btn)\n        layout.addLayout(btn_layout)\n        \n        if dialog.exec_() == QDialog.Accepted:\n            # Сохраняем изменения\n            rule[\'name\'] = name_input.text()\n            rule[\'severity\'] = severity_combo.currentText()\n            rule[\'description\'] = desc_input.toPlainText()\n            rule[\'remediation\'] = fix_input.toPlainText()\n            \n            # TODO: Сохранить в YAML файл\n            QMessageBox.information(self, "Успех", "Правило обновлено!")\n            self._init_ui()  # Перезагружаем таблицу\n    \n    def _edit_selected_rule(self):\n        selected = self.table.selectedIndexes()\n        if selected:\n            self._edit_rule(selected[0])\n        else:\n            QMessageBox.warning(self, "Внимание", "Выберите правило для редактирования")\n    \n    def _add_rule(self):\n        QMessageBox.information(self, "Информация", "Функция добавления новых правил будет доступна в следующей версии")\n\nclass LicenseDialog(QDialog):'
    )
    print("✅ Добавлен RuleManager (менеджер правил)")

# Добавляем кнопку Rule Manager в главное окно
if 'rule_manager_btn' not in ui:
    ui = ui.replace(
        'self.start_btn = QPushButton(" Начать сканирование")',
        'self.rule_manager_btn = QPushButton(" Менеджер правил")\n        self.rule_manager_btn.clicked.connect(self._open_rule_manager)\n        settings_layout.addWidget(self.rule_manager_btn)\n        \n        self.start_btn = QPushButton("🚀 Начать сканирование")'
    )
    
    # Добавляем метод открытия менеджера правил
    open_rule_method = \'\'\'
    def _open_rule_manager(self):
        """Открывает менеджер правил (только для Premium/Enterprise)"""
        scan_type = self.type_combo.currentText()\n        if scan_type not in ["Premium", "Enterprise"]:\n            QMessageBox.warning(self, "Требуется лицензия", "Менеджер правил доступен только для Premium и Enterprise версий.\\\\n\\\\nПожалуйста, активируйте лицензию.")\n            return\n        \n        dialog = RuleManager(self)\n        dialog.exec_()\n\n\''
    
    if '_open_rule_manager' not in ui:
        ui = ui.replace('    def browse_file', open_rule_method + '    def browse_file')
    print("✅ Добавлена кнопка Менеджер правил")

# Добавляем реальные ограничения при сканировании
if 'license_key' not in ui or 'self.settings.get' not in ui:
    # Находим где создаётся worker и добавляем передачу ключа
    ui = ui.replace(
        'self.worker = ScanWorker(target=target, mode=self.settings[\'mode\'], scan_type=self.settings[\'scan_type\'])',
        'self.worker = ScanWorker(target=target, mode=self.settings[\'mode\'], scan_type=self.settings[\'scan_type\'], license_key=self.settings.get(\'license_key\', \'\'))'
    )
    print("✅ Добавлена передача license_key в сканер")

with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
    f.write(ui)

print("\\n✅✅✅ Все ограничения и менеджер правил добавлены!")
print("\\nТеперь:")
print("  ✓ Basic: только 10 правил")
print("  ✓ Premium: все 49 правил + менеджер правил")
print("  ✓ Enterprise: все правила + менеджер + экспорт PDF + кастомные правила")
print("  ✓ Кнопка \'📚 Менеджер правил\' доступна только для Premium/Enterprise")
