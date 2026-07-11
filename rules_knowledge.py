import os
import yaml
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QListWidget, QTextEdit,
    QLineEdit, QPushButton, QLabel, QSplitter
)
from PyQt5.QtCore import Qt
from i18n import tr

class RulesKnowledgeWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(tr('rules_title'))
        self.setMinimumSize(900, 600)

        layout = QVBoxLayout(self)

        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(tr('rules_search_placeholder'))
        self.search_input.textChanged.connect(self.filter_rules)
        self.clear_btn = QPushButton("❌ Reset")
        self.clear_btn.clicked.connect(self.clear_search)
        search_layout.addWidget(QLabel(tr('rules_title').split()[0] + ":"))
        search_layout.addWidget(self.search_input, 1)
        search_layout.addWidget(self.clear_btn)
        layout.addLayout(search_layout)

        splitter = QSplitter(Qt.Horizontal)
        self.list_widget = QListWidget()
        self.list_widget.itemClicked.connect(self.show_rule_detail)
        splitter.addWidget(self.list_widget)

        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setHtml(f"<p style='color: gray;'>{tr('rules_no_selection')}</p>")
        splitter.addWidget(self.detail_text)

        splitter.setSizes([300, 600])
        layout.addWidget(splitter)

        self.rules = self.load_all_rules()
        self.all_items = list(self.rules.keys())
        self.populate_list(self.all_items)

    def load_all_rules(self):
        rules_dict = {}
        possible_paths = ["rules", "scanner/rules"]
        for base_path in possible_paths:
            if not os.path.exists(base_path):
                continue
            for filename in os.listdir(base_path):
                if filename.endswith(('.yaml', '.yml')):
                    filepath = os.path.join(base_path, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            data = yaml.safe_load(f)
                            if data and isinstance(data, dict):
                                if isinstance(data, list):
                                    for rule in data:
                                        if 'id' in rule or 'name' in rule:
                                            name = rule.get('name') or rule.get('id') or filename
                                            rules_dict[name] = rule
                                else:
                                    name = data.get('name') or data.get('id') or filename
                                    rules_dict[name] = data
                    except Exception as e:
                        print(f"Ошибка загрузки {filepath}: {e}")
        return rules_dict

    def populate_list(self, items):
        self.list_widget.clear()
        for name in sorted(items):
            self.list_widget.addItem(name)

    def filter_rules(self, text):
        if not text.strip():
            self.populate_list(self.all_items)
            self.detail_text.setHtml(f"<p style='color: gray;'>{tr('rules_no_selection')}</p>")
            return
        query = text.lower()
        filtered = []
        for name, rule in self.rules.items():
            desc = rule.get('description', '').lower()
            rec = rule.get('recommendation', '').lower()
            if query in name.lower() or query in desc or query in rec:
                filtered.append(name)
        self.populate_list(filtered)
        if not filtered:
            self.detail_text.setHtml(f"<p style='color: red;'>{tr('rules_not_found')}</p>")

    def clear_search(self):
        self.search_input.clear()
        self.populate_list(self.all_items)
        self.detail_text.setHtml(f"<p style='color: gray;'>{tr('rules_no_selection')}</p>")

    def show_rule_detail(self, item):
        name = item.text()
        rule = self.rules.get(name)
        if not rule:
            self.detail_text.setHtml("<p style='color: red;'>Information not found.</p>")
            return

        html = f"""
        <h2>{name}</h2>
        <p><b>{tr('rules_id')}</b> {rule.get('id', '—')}</p>
        <p><b>{tr('rules_severity')}</b> {rule.get('severity', 'unknown')}</p>
        <p><b>{tr('rules_description')}</b></p>
        <p>{rule.get('description', '—')}</p>
        <p><b>{tr('rules_recommendation')}</b></p>
        <pre style=" color: #e0e0e0;  border-radius: 5px; white-space: pre-wrap;">{rule.get('recommendation', '—')}</pre>
        """
        if 'example' in rule:
            html += f"<p><b>{tr('rules_example')}</b></p><pre style=' color: #d4d4d4;  border-radius: 5px;'>{rule['example']}</pre>"
        self.detail_text.setHtml(html)
