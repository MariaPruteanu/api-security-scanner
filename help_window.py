import sys
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QListWidget, QTextEdit,
    QLineEdit, QPushButton, QLabel, QSplitter
)
from PyQt5.QtCore import Qt
from i18n import tr
from help_docs import ERRORS, get_error_info, search_errors

class HelpWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(tr('help_title'))
        self.setMinimumSize(800, 500)

        layout = QVBoxLayout(self)

        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(tr('help_search_placeholder'))
        self.search_input.textChanged.connect(self.on_search)
        self.clear_btn = QPushButton("❌ Reset")
        self.clear_btn.clicked.connect(self.clear_search)
        search_layout.addWidget(QLabel(tr('help_search_placeholder').split()[0] + ":"))
        search_layout.addWidget(self.search_input, 1)
        search_layout.addWidget(self.clear_btn)
        layout.addLayout(search_layout)

        splitter = QSplitter(Qt.Horizontal)
        self.list_widget = QListWidget()
        self.list_widget.itemClicked.connect(self.on_item_clicked)
        splitter.addWidget(self.list_widget)

        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setHtml(f"<p style='color: gray;'>{tr('help_no_selection')}</p>")
        splitter.addWidget(self.text_edit)

        splitter.setSizes([300, 500])
        layout.addWidget(splitter)

        self.populate_list(ERRORS.keys())

    def populate_list(self, items):
        self.list_widget.clear()
        for name in items:
            self.list_widget.addItem(name)

    def on_search(self, text):
        if not text.strip():
            self.populate_list(ERRORS.keys())
            self.text_edit.setHtml(f"<p style='color: gray;'>{tr('help_no_selection')}</p>")
            return
        results = search_errors(text)
        if results:
            self.populate_list([name for name, _ in results])
        else:
            self.list_widget.clear()
            self.text_edit.setHtml(f"<p style='color: red;'>{tr('help_not_found')}</p>")

    def clear_search(self):
        self.search_input.clear()
        self.populate_list(ERRORS.keys())
        self.text_edit.setHtml(f"<p style='color: gray;'>{tr('help_no_selection')}</p>")

    def on_item_clicked(self, item):
        error_name = item.text()
        info = get_error_info(error_name)
        if info:
            html = f"""
            <h2>{error_name}</h2>
            <h3>{tr('help_description')}</h3>
            <p>{info['description']}</p>
            <h3>{tr('help_solution')}</h3>
            <pre style=" color: #e0e0e0;  border-radius: 5px; white-space: pre-wrap;">{info['solution']}</pre>
            """
            self.text_edit.setHtml(html)
        else:
            self.text_edit.setHtml("<p style='color: red;'>Information not found.</p>")
