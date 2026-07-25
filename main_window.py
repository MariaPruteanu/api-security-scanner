import sys
import os
import asyncio
import time
import json
import requests
import secrets
import importlib.util
import subprocess
import socket
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTextEdit, QFileDialog, QLineEdit,
    QProgressBar, QMessageBox, QTabWidget, QTableWidget, QTableWidgetItem,
    QComboBox, QDialog, QDialogButtonBox, QFormLayout, QInputDialog,
    QMenuBar, QMenu, QAction, QListWidget, QListWidgetItem,
    QCheckBox, QSpinBox, QComboBox as QComboTheme,
    QHeaderView, QFrame
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QIcon

from desktop_app.settings import load_settings, save_settings
from desktop_app.database import init_db, save_scan, get_history, get_scan, delete_scan, clear_history
from desktop_app.export import export_json, export_html, export_pdf
from i18n import tr, set_language
from update_checker import check_updates_async

DARK_STYLE = """
QMainWindow { background-color: #1a1a2e; }
QWidget { background-color: #16213e; color: #e0e0e0; }
QLabel { color: #e0e0e0; font-weight: bold; }
QLineEdit { background-color: #2a2a4a; border: 1px solid #4a4a6a; border-radius: 8px; padding: 6px 10px; color: #e0e0e0; }
QLineEdit:focus { border: 2px solid #7a7aff; }
QPushButton { background-color: #4a4a6a; border: none; border-radius: 8px; padding: 6px 12px; color: #e0e0e0; font-weight: bold; font-size: 12px; }
QPushButton:hover { background-color: #5a5a8a; }
QPushButton#scanBtn { background-color: #2e7d32; }
QPushButton#scanBtn:hover { background-color: #388e3c; }
QPushButton#scanBtn:disabled { background-color: #3a3a5a; color: #8888aa; }
QPushButton#stopBtn { background-color: #c62828; }
QPushButton#stopBtn:hover { background-color: #d32f2f; }
QPushButton#stopBtn:disabled { background-color: #3a3a5a; color: #8888aa; }
QComboBox { background-color: #2a2a4a; border: 1px solid #4a4a6a; border-radius: 8px; padding: 4px 8px; color: #e0e0e0; font-size: 12px; }
QComboBox::drop-down { border: none; }
QComboBox QAbstractItemView { background-color: #2a2a4a; color: #e0e0e0; selection-background-color: #4a4a6a; }
QProgressBar { background-color: #2a2a4a; border-radius: 10px; height: 16px; text-align: center; color: #e0e0e0; font-weight: bold; }
QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #4CAF50, stop:1 #7a7aff); border-radius: 10px; }
QTabWidget::pane { background-color: #16213e; border: 1px solid #4a4a6a; border-radius: 10px; }
QTabBar::tab { background-color: #2a2a4a; color: #aaaacc; padding: 6px 12px; border-top-left-radius: 6px; border-top-right-radius: 6px; margin-right: 2px; }
QTabBar::tab:selected { background-color: #4a4a6a; color: #ffffff; }
QTableWidget { background-color: #1a1a2e; alternate-background-color: #222244; color: #e0e0e0; gridline-color: #4a4a6a; border: none; }
QTableWidget::item:selected { background-color: #4a4a6a; }
QHeaderView::section { background-color: #2a2a4a; color: #e0e0e0; padding: 6px; border: 1px solid #4a4a6a; }
QTextEdit { background-color: #1a1a2e; color: #e0e0e0; border: 1px solid #4a4a6a; border-radius: 8px; }
QMenuBar { background-color: #16213e; color: #e0e0e0; }
QMenuBar::item:selected { background-color: #4a4a6a; }
QMenu { background-color: #2a2a4a; color: #e0e0e0; }
QMenu::item:selected { background-color: #4a4a6a; }
QMessageBox { background-color: #16213e; }
QMessageBox QLabel { color: #e0e0e0; }
QMessageBox QPushButton { background-color: #4a4a6a; border-radius: 6px; padding: 6px 12px; }
QListWidget { background-color: #1a1a2e; color: #e0e0e0; border: 1px solid #4a4a6a; border-radius: 8px; }
QListWidget::item:selected { background-color: #4a4a6a; }
QCheckBox { color: #e0e0e0; }
QSpinBox { background-color: #2a2a4a; color: #e0e0e0; border: 1px solid #4a4a6a; border-radius: 6px; padding: 4px; }
"""
LIGHT_STYLE = ""

class SeverityBadge(QLabel):
    def __init__(self, severity, parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignCenter)
        color_map = {
            'low': ('#3fb950', 'LOW'),
            'medium': ('#d29922', 'MEDIUM'),
            'high': ('#f85149', 'HIGH'),
            'critical': ('#bc4ed1', 'CRITICAL')
        }
        bg, text = color_map.get(severity.lower(), ('#8b949e', severity.upper()))
        self.setText(text)
        self.setStyleSheet(f"""
            background-color: {bg};
            color: #0d1117;
            border-radius: 12px;
            padding: 4px 12px;
            font-weight: 700;
            font-size: 11px;
        """)

class LicenseManager:
    VALID_PREMIUM_KEY = "PREMIUM-123"
    VALID_ENTERPRISE_KEY = "ENTERPRISE-456"

    @staticmethod
    def validate_key(key: str, level: str) -> bool:
        if level == 'premium':
            return key == LicenseManager.VALID_PREMIUM_KEY
        elif level == 'enterprise':
            return key == LicenseManager.VALID_ENTERPRISE_KEY
        return False

    @staticmethod
    def request_key(parent=None, level='premium') -> str:
        label = "Premium" if level == 'premium' else "Enterprise"
        key, ok = QInputDialog.getText(
            parent, f"{label} License",
            f"Enter license key for {label} mode:",
            QLineEdit.Password
        )
        return key if ok else ""

class CloudScanner:
    def __init__(self, api_key, base_url="http://127.0.0.1:8000"):
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.headers = {"Authorization": f"Bearer {api_key}"}

    def submit_scan(self, target, scan_type, timeout=30):
        try:
            resp = requests.post(
                f"{self.base_url}/api/v1/scan/submit",
                json={"target": target, "scan_type": scan_type},
                headers=self.headers,
                timeout=timeout
            )
            resp.raise_for_status()
            return resp.json()["task_id"]
        except Exception as e:
            raise Exception(f"Submit error: {e}")

    def get_status(self, task_id, timeout=5):
        try:
            resp = requests.get(
                f"{self.base_url}/api/v1/scan/status/{task_id}",
                headers=self.headers,
                timeout=timeout
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            raise Exception(f"Status error: {e}")

    def get_result(self, task_id, timeout=10):
        try:
            resp = requests.get(
                f"{self.base_url}/api/v1/scan/result/{task_id}",
                headers=self.headers,
                timeout=timeout
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            raise Exception(f"Result error: {e}")

class ScannerThread(QThread):
    finished = pyqtSignal(str)
    progress = pyqtSignal(int)
    error = pyqtSignal(str)
    stopped = pyqtSignal()

    def __init__(self, target, scan_type='basic', mode='local', api_key=None, api_url=None, timeout=30):
        super().__init__()
        self.target = target
        self.scan_type = scan_type
        self.mode = mode
        self.api_key = api_key
        self.api_url = api_url
        self.timeout = timeout
        self._is_stopped = False
        self.log_callback = None

    def stop(self):
        self._is_stopped = True

    def log(self, msg):
        if self.log_callback:
            self.log_callback(msg)
        print(msg)

    def _load_scanner(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        scanner_path = os.path.join(base_dir, 'scanner', 'core.py')
        if not os.path.exists(scanner_path):
            scanner_path = os.path.join(os.getcwd(), 'scanner', 'core.py')
        self.log(f"Scanner path: {scanner_path}")
        if not os.path.exists(scanner_path):
            self.log("Scanner/core.py not found!")
            raise ImportError("scanner/core.py not found")
        spec = importlib.util.spec_from_file_location("scanner.core", scanner_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.APIScanner

    def run(self):
        try:
            if self.mode == 'local':
                self.log("Starting local scan...")
                self.log(f"Target: {self.target}")

                try:
                    APIScanner = self._load_scanner()
                    self.log("Scanner.core loaded")
                except Exception as e:
                    self.log(f"Scanner load error: {e}")
                    self.error.emit(f"Scanner load error: {e}")
                    return

                resources_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                orig_dir = os.getcwd()
                os.chdir(resources_dir)

                try:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    scanner = APIScanner(base_url=self.target, timeout=self.timeout, scan_type=self.scan_type)
                    self.log("Running scan...")
                    raw_results = loop.run_until_complete(scanner.run_scan())
                    self.log(f"Scan complete, raw results: {len(raw_results)}")
                except Exception as e:
                    self.log(f"Scan error: {e}")
                    self.error.emit(f"Scan error: {e}")
                    return
                finally:
                    os.chdir(orig_dir)

                formatted = []
                for item in raw_results:
                    if isinstance(item, dict):
                        desc = item.get("description") or item.get("message") or f"{item.get('vulnerability', '')} {item.get('evidence', '')} {item.get('recommendation', '')}".strip()
                        if not desc:
                            desc = str(item)
                        formatted.append({
                            'id': item.get('id', str(len(formatted) + 1)),
                            'severity': item.get('severity', ''),
                            'description': desc
                        })
                    else:
                        desc = getattr(item, 'description', '') or getattr(item, 'message', '') or str(item)
                        formatted.append({
                            'id': getattr(item, 'id', str(len(formatted) + 1)),
                            'severity': getattr(item, 'severity', ''),
                            'description': desc
                        })
                self.log(f"Formatted records: {len(formatted)}")
                self.finished.emit(json.dumps(formatted, ensure_ascii=False))

            else:
                cloud = CloudScanner(api_key=self.api_key, base_url=self.api_url)
                task_id = cloud.submit_scan(self.target, self.scan_type, timeout=self.timeout)
                while not self._is_stopped:
                    status = cloud.get_status(task_id, timeout=self.timeout)
                    self.progress.emit(status.get('progress', 0))
                    if status['status'] == 'completed':
                        results = cloud.get_result(task_id, timeout=self.timeout)
                        self.finished.emit(json.dumps(results, ensure_ascii=False))
                        return
                    elif status['status'] == 'failed':
                        self.error.emit(status.get('error', 'Cloud scan failed'))
                        return
                    time.sleep(2)
                if self._is_stopped:
                    self.stopped.emit()

        except Exception as e:
            if not self._is_stopped:
                self.error.emit(str(e))

class HistoryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scan History")
        self.setMinimumSize(700, 450)
        self.setStyleSheet("""
            QDialog { background-color: #16213e; }
            QLabel { color: #e0e0e0; }
            QPushButton { background-color: #4a4a6a; border-radius: 8px; padding: 6px 14px; color: #e0e0e0; }
            QPushButton:hover { background-color: #5a5a8a; }
            QListWidget { background-color: #1a1a2e; border: 1px solid #4a4a6a; border-radius: 10px; color: #e0e0e0; }
            QListWidget::item:selected { background-color: #4a4a6a; }
        """)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        self.list = QListWidget()
        self.list.itemDoubleClicked.connect(self.show_scan_details)
        self.load_history()
        layout.addWidget(self.list)
        btn_layout = QHBoxLayout()
        self.delete_btn = QPushButton("Delete selected")
        self.delete_btn.clicked.connect(self.delete_selected)
        self.clear_btn = QPushButton("Clear all history")
        self.clear_btn.clicked.connect(self.clear_all)
        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(self.delete_btn)
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.close_btn)
        layout.addLayout(btn_layout)

    def load_history(self):
        self.list.clear()
        rows = get_history(100)
        for row in rows:
            id_, target, scan_type, timestamp, count = row
            item = QListWidgetItem(f"{timestamp} | {target} | {scan_type} | {count} findings")
            item.setData(Qt.UserRole, id_)
            self.list.addItem(item)

    def delete_selected(self):
        current = self.list.currentItem()
        if current:
            id_ = current.data(Qt.UserRole)
            delete_scan(id_)
            self.load_history()

    def clear_all(self):
        reply = QMessageBox.question(self, "Confirm", "Delete all history?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            clear_history()
            self.load_history()

    def show_scan_details(self, item):
        id_ = item.data(Qt.UserRole)
        results = get_scan(id_)
        if results:
            dlg = QDialog(self)
            dlg.setWindowTitle("Scan Results")
            dlg.setMinimumSize(700, 400)
            dlg.setStyleSheet("""
                QDialog { background-color: #16213e; }
                QTableWidget { background-color: #1a1a2e; color: #e0e0e0; gridline-color: #4a4a6a; border: none; }
                QHeaderView::section { background-color: #2a2a4a; color: #e0e0e0; }
                QPushButton { background-color: #4a4a6a; border-radius: 8px; padding: 6px 14px; color: #e0e0e0; }
                QPushButton:hover { background-color: #5a5a8a; }
            """)
            layout = QVBoxLayout(dlg)
            table = QTableWidget()
            table.setColumnCount(3)
            table.setHorizontalHeaderLabels(["ID", "Severity", "Description"])
            table.setRowCount(len(results))
            table.setAlternatingRowColors(True)
            for i, r in enumerate(results):
                table.setItem(i, 0, QTableWidgetItem(r.get('id', '')))
                severity = r.get('severity', 'unknown')
                badge = SeverityBadge(severity)
                table.setCellWidget(i, 1, badge)
                table.setItem(i, 2, QTableWidgetItem(r.get('description', '')))
            table.resizeColumnsToContents()
            table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
            layout.addWidget(table)
            btn = QPushButton("Close")
            btn.clicked.connect(dlg.accept)
            layout.addWidget(btn, alignment=Qt.AlignRight)
            dlg.exec_()

class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.settings = load_settings()
        self.setWindowTitle("Settings")
        self.setMinimumWidth(450)
        self.setStyleSheet("""
            QDialog { background-color: #16213e; }
            QLabel { color: #e0e0e0; }
            QLineEdit, QSpinBox, QComboBox {
                background-color: #2a2a4a;
                border: 1px solid #4a4a6a;
                border-radius: 8px;
                padding: 6px 10px;
                color: #e0e0e0;
            }
            QCheckBox { color: #e0e0e0; }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 4px;
                border: 2px solid #4a4a6a;
                background-color: #2a2a4a;
            }
            QCheckBox::indicator:checked {
                background-color: #4a4a6a;
                border-color: #7a7aff;
            }
            QPushButton {
                background-color: #4a4a6a;
                border-radius: 8px;
                padding: 6px 16px;
                color: #e0e0e0;
            }
            QPushButton:hover {
                background-color: #5a5a8a;
            }
        """)
        self.init_ui()

    def init_ui(self):
        layout = QFormLayout(self)
        layout.setSpacing(12)

        self.theme_combo = QComboTheme()
        self.theme_combo.addItems(["Dark", "Light"])
        self.theme_combo.setCurrentIndex(0 if self.settings.get('theme') == 'dark' else 1)
        layout.addRow("Theme:", self.theme_combo)

        self.lang_combo = QComboBox()
        from i18n import TRANSLATIONS
        self.lang_combo.addItems(list(TRANSLATIONS.keys()))
        self.lang_combo.setCurrentText(self.settings.get("language", "ru"))
        layout.addRow("Language:", self.lang_combo)

        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 300)
        self.timeout_spin.setValue(self.settings.get('timeout', 30))
        layout.addRow("Request timeout (sec):", self.timeout_spin)

        self.save_history_cb = QCheckBox()
        self.save_history_cb.setChecked(self.settings.get('save_history', True))
        layout.addRow("Save history:", self.save_history_cb)

        self.max_history_spin = QSpinBox()
        self.max_history_spin.setRange(10, 500)
        self.max_history_spin.setValue(self.settings.get('max_history', 50))
        layout.addRow("Max history records:", self.max_history_spin)

        self.premium_key_edit = QLineEdit()
        self.premium_key_edit.setEchoMode(QLineEdit.Password)
        self.premium_key_edit.setText(self.settings.get('premium_key', ''))
        layout.addRow("Premium key:", self.premium_key_edit)

        self.enterprise_key_edit = QLineEdit()
        self.enterprise_key_edit.setEchoMode(QLineEdit.Password)
        self.enterprise_key_edit.setText(self.settings.get('enterprise_key', ''))
        layout.addRow("Enterprise key:", self.enterprise_key_edit)

        self.api_url_edit = QLineEdit()
        self.api_url_edit.setText(self.settings.get('api_url', 'http://127.0.0.1:8000'))
        layout.addRow("Backend URL:", self.api_url_edit)

        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.accepted.connect(self.save)
        btn_box.rejected.connect(self.reject)
        layout.addRow(btn_box)

    def save(self):
        self.settings['theme'] = 'dark' if self.theme_combo.currentIndex() == 0 else 'light'
        self.settings['timeout'] = self.timeout_spin.value()
        self.settings['save_history'] = self.save_history_cb.isChecked()
        self.settings['max_history'] = self.max_history_spin.value()
        self.settings['premium_key'] = self.premium_key_edit.text()
        self.settings['enterprise_key'] = self.enterprise_key_edit.text()
        self.settings['api_url'] = self.api_url_edit.text()
        self.settings['language'] = self.lang_combo.currentText()
        save_settings(self.settings)
        from i18n import set_language
        set_language(self.settings['language'])
        parent = self.parent()
        if parent and hasattr(parent, 'retranslate_ui'):
            parent.retranslate_ui()
        self.accept()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = load_settings()
        self.license_valid = {'premium': False, 'enterprise': False}
        self.setWindowTitle("API Security Scanner Pro")

        icon_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app_icon.icns")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        else:
            png_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app_icon.png")
            if os.path.exists(png_path):
                self.setWindowIcon(QIcon(png_path))

        self.setMinimumSize(1000, 700)
        self.scanner_thread = None
        self.current_results = []
        self.api_key = self.settings.get('api_key', '')
        self.api_url = self.settings.get('api_url', 'http://127.0.0.1:8000')
        self.timeout = self.settings.get('timeout', 30)

        self.init_ui()
        set_language(self.settings.get("language", "ru"))
        self.retranslate_ui()
        self.apply_theme()
        self.init_db()

        last = self.settings.get('last_target', '')
        if last:
            self.target_input.setText(last)

    def init_db(self):
        init_db()

    def apply_theme(self):
        theme = self.settings.get('theme', 'dark')
        if theme == 'dark':
            self.setStyleSheet(DARK_STYLE)
        else:
            self.setStyleSheet(LIGHT_STYLE)

    def init_ui(self):
        menubar = self.menuBar()

        self.file_menu = menubar.addMenu("File")
        self.export_menu = self.file_menu.addMenu("Export report")
        for fmt, label in [('json', 'JSON'), ('html', 'HTML'), ('pdf', 'PDF')]:
            action = QAction(label, self)
            action.triggered.connect(lambda checked, f=fmt: self.export_report(f))
            self.export_menu.addAction(action)
        self.file_menu.addSeparator()
        report_action = QAction("Generate report", self)
        report_action.triggered.connect(self.generate_report)
        self.file_menu.addAction(report_action)
        self.file_menu.addSeparator()
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        self.file_menu.addAction(exit_action)

        history_menu = menubar.addMenu("History")
        show_history = QAction("Show history", self)
        show_history.triggered.connect(self.show_history)
        history_menu.addAction(show_history)

        settings_menu = menubar.addMenu("Settings")
        settings_action = QAction("Options", self)
        settings_action.triggered.connect(self.open_settings)
        settings_menu.addAction(settings_action)

        help_menu = menubar.addMenu("Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        help_action = QAction("Help", self)
        help_action.triggered.connect(self.open_help)
        help_menu.addAction(help_action)
        rules_action = QAction("Rules knowledge base", self)
        rules_action.triggered.connect(self.open_rules_knowledge)
        help_menu.addAction(rules_action)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(16)
        main_layout.setContentsMargins(30, 20, 30, 20)

        title_layout = QHBoxLayout()
        title_label = QLabel("API Security Scanner Pro")
        title_label.setStyleSheet("font-size: 20px; font-weight: bold; color: #e0e0e0;")
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        version_label = QLabel("v1.0")
        version_label.setStyleSheet("color: #8b949e; font-size: 14px;")
        title_layout.addWidget(version_label)
        main_layout.addLayout(title_layout)

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("background-color: #4a4a6a; max-height: 1px;")
        main_layout.addWidget(line)

        row1 = QHBoxLayout()
        row1.setSpacing(8)
        self.target_label = QLabel("Target:")
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter OpenAPI URL or select file...")
        self.target_input.setMinimumWidth(350)
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_file)
        row1.addWidget(self.target_label)
        row1.addWidget(self.target_input, 1)
        row1.addWidget(self.browse_btn)
        main_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.setSpacing(10)

        row2.addWidget(QLabel("Mode:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Local", "Cloud"])
        self.mode_combo.setCurrentIndex(0)
        self.mode_combo.currentIndexChanged.connect(self.on_mode_changed)
        row2.addWidget(self.mode_combo)

        row2.addWidget(QLabel("Type:"))
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Basic (Free)", "Premium (Paid)", "Enterprise (Pro)"])
        self.scan_type_combo.setCurrentIndex(0)
        row2.addWidget(self.scan_type_combo)

        self.api_key_input = QLineEdit()
        self.api_key_input.setPlaceholderText("API Key")
        self.api_key_input.setEchoMode(QLineEdit.Password)
        self.api_key_input.setFixedWidth(120)
        if self.api_key:
            self.api_key_input.setText(self.api_key)
        row2.addWidget(self.api_key_input)

        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.setObjectName("scanBtn")
        self.scan_btn.setFixedWidth(130)
        self.scan_btn.clicked.connect(self.start_scan)
        row2.addWidget(self.scan_btn)

        self.lang_btn = QPushButton("RU" if self.settings.get("language", "ru") == "ru" else "EN")
        self.lang_btn.setFixedWidth(40)
        self.lang_btn.clicked.connect(self.toggle_language)
        row2.addWidget(self.lang_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setFixedWidth(80)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_scan)
        row2.addWidget(self.stop_btn)

        self.pro_btn = QPushButton("Buy Pro")
        self.pro_btn.clicked.connect(self.buy_pro)
        row2.addWidget(self.pro_btn)

        row2.addStretch(1)
        main_layout.addLayout(row2)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Ready")
        main_layout.addWidget(self.progress_bar)

        self.tabs = QTabWidget()
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["ID", "Severity", "Description"])
        self.results_table.setAlternatingRowColors(True)
        self.results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setWordWrap(True)
        self.tabs.addTab(self.results_table, "Results")

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Menlo", 10))
        self.tabs.addTab(self.log_text, "Log")
        main_layout.addWidget(self.tabs, 1)

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #8b949e; padding: 6px 0;")
        main_layout.addWidget(self.status_label)

        self.on_mode_changed(0)
        self._load_keys()

    def _load_keys(self):
        try:
            if self.settings.get('premium_key') and LicenseManager.validate_key(self.settings['premium_key'], 'premium'):
                self.license_valid['premium'] = True
                print("Premium key loaded from settings")
            if self.settings.get('enterprise_key') and LicenseManager.validate_key(self.settings['enterprise_key'], 'enterprise'):
                self.license_valid['enterprise'] = True
                print("Enterprise key loaded from settings")
            self.update_usage_status()
        except Exception as e:
            print(f"Error loading keys: {e}")

    def on_mode_changed(self, index):
        if index == 1:
            self.scan_type_combo.setEnabled(False)
        else:
            self.scan_type_combo.setEnabled(True)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select OpenAPI specification",
            "", "YAML/JSON (*.yaml *.yml *.json)"
        )
        if file_path:
            self.target_input.setText(file_path)

    def _is_backend_running(self):
        try:
            with socket.create_connection(("127.0.0.1", 8000), timeout=1):
                return True
        except:
            return False

    def _open_terminal_with_command(self):
        if hasattr(sys, '_MEIPASS'):
            base_dir = sys._MEIPASS
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cmd = f"cd {base_dir} && /usr/bin/python3 -m uvicorn main:app --host 0.0.0.0 --port 8000"
        script = f'''
        tell application "Terminal"
            activate
            do script "{cmd}"
        end tell
        '''
        try:
            subprocess.Popen(['osascript', '-e', script])
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open terminal: {e}")

    def _ensure_backend_running(self):
        if self._is_backend_running():
            self.append_log("Backend already running")
            return True
        self.append_log("Starting backend...")
        try:
            import subprocess, time
            if hasattr(sys, '_MEIPASS'):
                base_dir = sys._MEIPASS
            else:
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            cmd = [sys.executable, "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
            subprocess.Popen(cmd, cwd=base_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)
            if self._is_backend_running():
                self.append_log("Backend started successfully")
                return True
            else:
                self.append_log("Backend failed to start. Try manual.")
                return False
        except Exception as e:
            self.append_log(f"Backend start error: {e}")
            return False

    def toggle_language(self):
        from i18n import set_language
        current = self.settings.get("language", "ru")
        new_lang = "en" if current == "ru" else "ru"
        self.settings["language"] = new_lang
        save_settings(self.settings)
        set_language(new_lang)
        self.retranslate_ui()
        self.lang_btn.setText("EN" if new_lang == "ru" else "RU")

    def start_scan(self):
        print("start_scan called!")
        try:
            target = self.target_input.text().strip()
            if not target:
                QMessageBox.warning(self, "Warning", "Please enter a target URL or file.")
                return

            mode = 'local' if self.mode_combo.currentIndex() == 0 else 'cloud'
            scan_type_index = self.scan_type_combo.currentIndex()
            if scan_type_index == 0:
                scan_type = "basic"
            elif scan_type_index == 1:
                scan_type = "premium"
            else:
                scan_type = "enterprise"

            if mode == 'cloud':
                if not self._ensure_backend_running():
                    self.append_log("Backend not running, cannot scan")
                    return
                api_key = self.api_key_input.text().strip()
                if not api_key:
                    QMessageBox.warning(self, "API key required", "Please enter your API key for cloud mode.")
                    return
                self.api_key = api_key
                self.settings['api_key'] = api_key
                save_settings(self.settings)

            if scan_type in ("premium", "enterprise") and not self.license_valid.get(scan_type, False):
                key = LicenseManager.request_key(self, scan_type)
                if key and LicenseManager.validate_key(key, scan_type):
                    self.license_valid[scan_type] = True
                    self.settings[f"{scan_type}_key"] = key
                    save_settings(self.settings)
                    self.update_usage_status()
                    print(f"{scan_type.capitalize()} key saved")
                else:
                    QMessageBox.warning(self, "Error", f"Invalid key for {scan_type.capitalize()}.")
                    return

            self.scan_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("Preparing...")
            self.results_table.setRowCount(0)
            self.log_text.clear()
            self.status_label.setText(f"Scanning in {mode} mode ({scan_type})...")

            self.scanner_thread = ScannerThread(
                target=target,
                scan_type=scan_type,
                mode=mode,
                api_key=self.api_key if mode == 'cloud' else None,
                api_url=self.api_url,
                timeout=self.settings.get('timeout', 30)
            )
            self.scanner_thread.log_callback = self.append_log
            self.scanner_thread.progress.connect(self.update_progress)
            self.scanner_thread.finished.connect(self.on_scan_finished)
            self.scanner_thread.error.connect(self.on_scan_error)
            self.scanner_thread.stopped.connect(self.on_scan_stopped)
            self.scanner_thread.start()

        except Exception as e:
            self.scan_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.status_label.setText("Error")
            self.progress_bar.setFormat("Error")
            import traceback
            traceback.print_exc()
            QMessageBox.critical(self, "Error", f"Unexpected error:\n{str(e)}")

    def append_log(self, msg):
        self.log_text.append(msg)
        self.log_text.moveCursor(self.log_text.textCursor().End)

    def stop_scan(self):
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.stop()
            self.status_label.setText("Stopping...")
            self.stop_btn.setEnabled(False)
            self.progress_bar.setFormat("Stopping...")

    def on_scan_stopped(self):
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Scan stopped by user")
        self.progress_bar.setFormat("Stopped")
        QMessageBox.information(self, "Stopped", "Scan cancelled by user.")

    def update_progress(self, value):
        self.progress_bar.setValue(value)
        if value < 20:
            self.progress_bar.setFormat("Collecting data...")
        elif value < 40:
            self.progress_bar.setFormat("Analyzing vulnerabilities...")
        elif value < 70:
            self.progress_bar.setFormat("Checking rules...")
        elif value < 90:
            self.progress_bar.setFormat("Generating report...")
        else:
            self.progress_bar.setFormat("Finishing...")

    def on_scan_finished(self, results_json):
        try:
            print("on_scan_finished, JSON length:", len(results_json))
            data = json.loads(results_json)

            if isinstance(data, dict):
                if 'results' in data:
                    raw_results = data['results']
                else:
                    raw_results = list(data.values())
            else:
                raw_results = data

            if isinstance(raw_results, dict):
                raw_results = list(raw_results.values())

            safe_results = []
            for idx, item in enumerate(raw_results):
                if isinstance(item, dict):
                    safe_item = {
                        'id': item.get('id', str(idx + 1)),
                        'severity': item.get('severity', 'UNKNOWN'),
                        'description': item.get('description', str(item))
                    }
                elif isinstance(item, str):
                    safe_item = {
                        'id': str(idx + 1),
                        'severity': 'UNKNOWN',
                        'description': item
                    }
                else:
                    safe_item = {
                        'id': str(idx + 1),
                        'severity': 'UNKNOWN',
                        'description': str(item)
                    }
                safe_results.append(safe_item)

            print(f"Results processed: {len(safe_results)}")

        except Exception as e:
            self.scan_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("Error")
            self.status_label.setText(f"Processing error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to process results: {str(e)}")
            return

        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("Scan complete")
        self.status_label.setText(f"Found {len(safe_results)} vulnerabilities.")
        self.current_results = safe_results
        self.display_results(safe_results)

        if self.settings.get('save_history', True):
            mode = 'local' if self.mode_combo.currentIndex() == 0 else 'cloud'
            scan_type = self.scan_type_combo.currentText().split()[0].lower()
            save_scan(self.target_input.text().strip(), f"{mode}-{scan_type}", safe_results)

    def on_scan_error(self, error_msg):
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Error")
        self.progress_bar.setFormat("Error")
        user_friendly = error_msg
        if "Connection refused" in error_msg:
            user_friendly = "Could not connect to cloud server. Check backend is running."
        elif "401" in error_msg:
            user_friendly = "Invalid API key. Check your settings."
        elif "500" in error_msg:
            user_friendly = "Server error. Please try later."
        QMessageBox.critical(self, "Scan error", user_friendly)

    def display_results(self, results):
        safe_results = []
        for idx, item in enumerate(results):
            if isinstance(item, dict):
                safe_item = {
                    'id': item.get('id', str(idx + 1)),
                    'severity': item.get('severity', 'UNKNOWN'),
                    'description': item.get('description', str(item))
                }
            elif isinstance(item, str):
                safe_item = {
                    'id': str(idx + 1),
                    'severity': 'UNKNOWN',
                    'description': item
                }
            else:
                safe_item = {
                    'id': str(idx + 1),
                    'severity': 'UNKNOWN',
                    'description': str(item)
                }
            safe_results.append(safe_item)

        self.results_table.setRowCount(len(safe_results))
        for row, item in enumerate(safe_results):
            self.results_table.setItem(row, 0, QTableWidgetItem(str(item.get('id', ''))))
            severity = item.get('severity', 'unknown')
            badge = SeverityBadge(severity)
            self.results_table.setCellWidget(row, 1, badge)
            self.results_table.setItem(row, 2, QTableWidgetItem(item.get('description', '')))
        self.results_table.resizeRowsToContents()
        self.results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)

    def export_report(self, fmt):
        if not self.current_results:
            QMessageBox.warning(self, "No data", "Please run a scan first.")
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self, f"Save report as {fmt.upper()}",
            f"scan_report.{fmt}",
            f"{fmt.upper()} files (*.{fmt})"
        )
        if file_path:
            try:
                if fmt == 'json':
                    export_json(self.current_results, file_path)
                elif fmt == 'html':
                    export_html(self.current_results, file_path)
                elif fmt == 'pdf':
                    export_pdf(self.current_results, file_path)
                QMessageBox.information(self, "Success", f"Report saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save: {e}")

    def show_history(self):
        dlg = HistoryDialog(self)
        dlg.exec_()

    def open_settings(self):
        dlg = SettingsDialog(self)
        if dlg.exec_() == QDialog.Accepted:
            self.settings = load_settings()
            self.apply_theme()
            self.api_key = self.settings.get('api_key', '')
            self.api_url = self.settings.get('api_url', 'http://127.0.0.1:8000')
            self.timeout = self.settings.get('timeout', 30)
            if self.api_key:
                self.api_key_input.setText(self.api_key)
            if self.settings.get('premium_key') and LicenseManager.validate_key(
                    self.settings['premium_key'], 'premium'):
                self.license_valid['premium'] = True
            if self.settings.get('enterprise_key') and LicenseManager.validate_key(
                    self.settings['enterprise_key'], 'enterprise'):
                self.license_valid['enterprise'] = True
            last = self.settings.get('last_target', '')
            if last:
                self.target_input.setText(last)
            set_language(self.settings.get("language", "ru"))
            self.retranslate_ui()

    def show_about(self):
        QMessageBox.about(self, "About",
                          "API Security Scanner Pro v4.6\n\n"
                          "Desktop application for API vulnerability scanning.\n"
                          "Author: Maria Pruteanu\n"
                          "License: MIT\n"
                          "Uses OWASP API Security Top 10.\n\n"
                          "Scan types:\n"
                          " Basic (Free) - basic checks\n"
                          " Premium (Paid) - all checks\n"
                          " Enterprise (Pro) - all checks + extended features\n\n"
                          "Cloud mode requires running backend. Terminal will open if needed.")

    def generate_report(self):
        try:
            import subprocess, sqlite3
            conn = sqlite3.connect("scanner.db")
            c = conn.cursor()
            c.execute("SELECT id FROM scan_tasks ORDER BY id DESC LIMIT 1")
            row = c.fetchone()
            conn.close()
            if row:
                scan_id = row[0]
                subprocess.Popen(["python", "run_report.py", str(scan_id)])
                QMessageBox.information(self, "Success", f"Report for scan #{scan_id} is being generated")
            else:
                QMessageBox.information(self, "Info", "No completed scans found")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate report: {e}")

    def open_help(self):
        from help_window import HelpWindow
        dlg = HelpWindow(self)
        dlg.exec_()

    def open_rules_knowledge(self):
        from rules_knowledge import RulesKnowledgeWindow
        dlg = RulesKnowledgeWindow(self)
        dlg.exec_()

    def retranslate_ui(self):
        self.setWindowTitle(tr('app_title'))
        self.scan_btn.setText(tr('start_scan_btn'))
        self.stop_btn.setText(tr('stop_scan_btn'))
        self.target_label.setText(tr('target_label'))
        self.browse_btn.setText(tr('browse_btn'))
        self.mode_combo.setItemText(0, tr('mode_local'))
        self.mode_combo.setItemText(1, tr('mode_cloud'))
        self.scan_type_combo.setItemText(0, tr('type_basic'))
        self.scan_type_combo.setItemText(1, tr('type_premium'))
        self.scan_type_combo.setItemText(2, tr('type_enterprise'))
        self.api_key_input.setPlaceholderText(tr('api_key_placeholder'))
        self.status_label.setText(tr('status_ready'))
        self.progress_bar.setFormat(tr('progress_ready'))
        self.results_table.setHorizontalHeaderLabels([tr('table_id'), tr('table_severity'), tr('table_description')])
        if hasattr(self, 'file_menu'):
            self.file_menu.setTitle(tr('menu_file'))
        if hasattr(self, 'export_menu'):
            self.export_menu.setTitle(tr('menu_export'))

    def update_usage_status(self):
        is_premium = self.license_valid.get('premium', False)
        is_enterprise = self.license_valid.get('enterprise', False)
        from desktop_usage import get_tier_label, get_remaining_scans
        tier = get_tier_label(is_premium, is_enterprise)
        if is_premium or is_enterprise:
            scans_text = "unlimited"
        else:
            remaining = get_remaining_scans()
            scans_text = f"{remaining} of 5"
        self.status_label.setText(f"Plan: {tier} | Scans left: {scans_text}")

    def buy_pro(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Payment")
        dialog.setMinimumWidth(450)
        layout = QVBoxLayout(dialog)

        label = QLabel("Select payment method:")
        layout.addWidget(label)

        self.check_defi = QCheckBox("DeFi (USDT/Solana) - international")
        self.check_boosty = QCheckBox("Boosty - Russia (rubles)")
        layout.addWidget(self.check_defi)
        layout.addWidget(self.check_boosty)

        plan_label = QLabel("Select plan:")
        layout.addWidget(plan_label)
        self.plan_combo = QComboBox()
        self.plan_combo.addItem("Monthly (9 USDT / 810 RUB)")
        self.plan_combo.addItem("Yearly (74.25 USDT / 6682.5 RUB) - 25% off")
        layout.addWidget(self.plan_combo)

        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.accepted.connect(dialog.accept)
        btn_box.rejected.connect(dialog.reject)
        layout.addWidget(btn_box)

        if dialog.exec_() == QDialog.Accepted:
            if self.check_defi.isChecked():
                plan = "monthly" if self.plan_combo.currentIndex() == 0 else "yearly"
                self._defi_payment_dialog(plan)
            elif self.check_boosty.isChecked():
                import webbrowser
                webbrowser.open("https://boosty.to/mariapruteanu")
            else:
                QMessageBox.warning(self, "Warning", "Please select a payment method.")

    def _defi_payment_dialog(self, plan="monthly"):
        try:
            import requests
            resp = requests.get(f"{self.api_url}/api/payment/defi/info", params={"plan": plan}, timeout=60)
            if resp.status_code != 200:
                QMessageBox.warning(self, "Error", "Failed to get payment info.")
                return
            data = resp.json()
            plan_label = "Monthly" if plan == "monthly" else "Yearly (25% discount)"
            msg = f"""
Plan: {plan_label}
Amount: {data['amount']} USDT

Network: {data['network']}
Address: {data['wallet']}
Memo: {data['memo']}

After payment, click "Check payment".
"""
            reply = QMessageBox.question(
                self, "DeFi Payment",
                msg,
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            if reply == QMessageBox.Yes:
                from PyQt5.QtWidgets import QApplication
                clipboard = QApplication.clipboard()
                clipboard.setText(data['wallet'])
                QMessageBox.information(self, "Address copied", "Wallet address copied to clipboard.")
                self._check_payment()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error: {e}")

    
    def _check_payment(self):
        """Проверяет, была ли оплата на DeFi-кошелёк."""
        try:
            import requests
            self.append_log("Checking payment status...")
            resp = requests.post(f"{self.api_url}/api/payment/defi/check", timeout=60)
            self.append_log(f"Response status: {resp.status_code}")
            if resp.status_code == 200:
                data = resp.json()
                self.append_log(f"Response data: {data}")
                if data.get('success'):
                    self.license_valid['premium'] = True
                    self.settings['premium_key'] = "PAID-VIA-DEFI"
                    save_settings(self.settings)
                    self.update_usage_status()
                    QMessageBox.information(self, "Success!", data.get('message', 'License activated!'))
                else:
                    QMessageBox.warning(
                        self, 
                        "Payment not found", 
                        data.get('message', 'No transaction found. Please make sure you sent USDT to the correct address.')
                    )
            else:
                QMessageBox.warning(self, "Error", f"Server error: {resp.status_code}")
        except requests.exceptions.Timeout:
            QMessageBox.critical(self, "Timeout", "The request timed out. Please try again.")
        except requests.exceptions.ConnectionError:
            QMessageBox.critical(self, "Connection Error", "Could not connect to the backend. Make sure it's running.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Check error: {e}")
def closeEvent(self, event):
        self.settings['last_target'] = self.target_input.text().strip()
        save_settings(self.settings)
        event.accept()

def run():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    run()
