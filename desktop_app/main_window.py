#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, os, json, asyncio, csv, html
from datetime import datetime
from typing import List, Dict
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QComboBox, QProgressBar, QTabWidget, QFileDialog, QMessageBox, QDialog)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont
from purchase_dialog import PurchaseDialog

SETTINGS_FILE = os.path.join(os.path.expanduser("~"), ".apiscanner_settings.json")

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f: return json.load(f)
        except: pass
    return {'target': '', 'mode': 'local', 'scan_type': 'basic', 'language': 'ru', 'license_key': ''}

def save_settings(s):
    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f: json.dump(s, f, ensure_ascii=False, indent=2)
    except: pass

TRANSLATIONS = {
    'ru': {'title': '🛡️ API Security Scanner Pro v2.0', 'target': '🎯 Цель:', 'browse': '📁 Обзор',
           'mode': 'Режим:', 'type': 'Тип:', 'lang': 'Язык:', 'start': '🚀 Начать сканирование',
           'rules': '📚 Менеджер правил', 'res_tab': '📊 Результаты', 'log_tab': '📝 Лог',
           'col_id': 'ID', 'col_sev': 'Критичность', 'col_desc': 'Описание', 'col_fix': 'Как исправить'},
    'en': {'title': '🛡️ API Security Scanner Pro v2.0', 'target': '🎯 Target:', 'browse': '📁 Browse',
           'mode': 'Mode:', 'type': 'Type:', 'lang': 'Language:', 'start': '🚀 Start Scan',
           'rules': '📚 Rule Manager', 'res_tab': '📊 Results', 'log_tab': '📝 Log',
           'col_id': 'ID', 'col_sev': 'Severity', 'col_desc': 'Description', 'col_fix': 'How to Fix'}
}

class RuleManager(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("📚 Rule Manager")
        self.setMinimumSize(900, 600)
        self.setModal(True)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<h2>Security Rules Management</h2>"))
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["ID", "Name", "Severity", "Description"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        layout.addWidget(self.table)
        try:
            from scanner.rules_loader import RulesLoader
            self.rules = RulesLoader().get_all_rules()
            self.table.setRowCount(len(self.rules))
            for i, r in enumerate(self.rules):
                self.table.setItem(i, 0, QTableWidgetItem(r.get('id', '')))
                self.table.setItem(i, 1, QTableWidgetItem(r.get('name', r.get('id', ''))))
                self.table.setItem(i, 2, QTableWidgetItem(r.get('severity', 'medium').upper()))
                self.table.setItem(i, 3, QTableWidgetItem(r.get('description', '')[:80]))
        except Exception as e:
            layout.addWidget(QLabel(f"Error: {e}"))
        close_btn = QPushButton("Close"); close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)

class SeverityBadge(QLabel):
    COLORS = {'critical': '#9b59b6', 'high': '#e74c3c', 'medium': '#f39c12', 'low': '#3498db', 'info': '#2ecc71'}
    def __init__(self, severity: str, parent=None):
        super().__init__(parent)
        self.severity = severity.lower()
        self.setText(self.severity.upper())
        self.setAlignment(Qt.AlignCenter)
        self.setStyleSheet(f"background-color: {self.COLORS.get(self.severity, '#95a5a6')}; color: white; font-weight: bold; border-radius: 6px; padding: 4px;")

class ScanWorker(QThread):
    log_signal = pyqtSignal(str)
    result_signal = pyqtSignal(list)
    error_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()
    def __init__(self, target, mode, scan_type, timeout=30, license_key=""):
        super().__init__()
        self.target, self.mode, self.scan_type, self.timeout, self.license_key = target, mode, scan_type, timeout, license_key
    def run(self):
        try:
            self.log_signal.emit(f"🔍 Starting scan ({self.scan_type.upper()})...")
            import importlib.util
            scanner_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'scanner', 'core.py')
            spec = importlib.util.spec_from_file_location("scanner.core", scanner_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            orig_dir = os.getcwd()
            os.chdir(os.path.dirname(os.path.dirname(__file__)))
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                scanner = module.APIScanner(base_url=self.target, timeout=self.timeout, scan_type=self.scan_type, license_key=self.license_key)
                results = loop.run_until_complete(scanner.run_scan())
                self.result_signal.emit(results)
            finally: os.chdir(orig_dir)
        except Exception as e: self.error_signal.emit(str(e))
        finally: self.finished_signal.emit()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = load_settings()
        self.current_lang = self.settings.get('language', 'ru')
        self.last_results = []
        lic_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'license.key')
        if os.path.exists(lic_file):
            try:
                with open(lic_file, 'r', encoding='utf-8') as f:
                    self.settings['license_key'] = f.read().strip()
                    save_settings(self.settings)
            except: pass
        self.worker = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle(TRANSLATIONS[self.current_lang]['title'])
        self.setMinimumSize(950, 700)
        self.setStyleSheet("""
            QMainWindow { background-color: #1a1a2e; }
            QLabel { color: #e0e0e0; font-size: 14px; }
            QLineEdit, QComboBox { background-color: #16213e; color: #e0e0e0; border: 1px solid #0f3460; border-radius: 6px; padding: 8px; }
            QPushButton { background-color: #0f3460; color: white; border: none; border-radius: 6px; padding: 10px 20px; font-weight: bold; }
            QPushButton:hover { background-color: #1a5276; }
            #startBtn { background-color: #27ae60; }
            QTextEdit, QTableWidget { background-color: #16213e; color: #e0e0e0; border: 1px solid #0f3460; border-radius: 6px; }
            QHeaderView::section { background-color: #0f3460; color: white; padding: 8px; }
            QTabBar::tab { background-color: #16213e; color: #e0e0e0; padding: 10px 20px; border: 1px solid #0f3460; border-bottom: none; }
            QTabBar::tab:selected { background-color: #0f3460; color: white; }
        """)
        central = QWidget(); self.setCentralWidget(central)
        layout = QVBoxLayout(central); layout.setSpacing(15); layout.setContentsMargins(20, 20, 20, 20)
        layout.addWidget(QLabel("<h1 style='color:#e94560;'>🛡️ API Security Scanner Pro</h1>"))
        t_layout = QHBoxLayout()
        t_layout.addWidget(QLabel(TRANSLATIONS[self.current_lang]['target']))
        self.target_input = QLineEdit()
        self.target_input.setText(self.settings.get('target', 'https://petstore.swagger.io/v2/swagger.json'))
        t_layout.addWidget(self.target_input, 1)
        browse = QPushButton(TRANSLATIONS[self.current_lang]['browse'])
        browse.clicked.connect(lambda: self.target_input.setText(QFileDialog.getOpenFileName(self, "OpenAPI", "", "JSON (*.json)")[0]))
        t_layout.addWidget(browse); layout.addLayout(t_layout)
        s_layout = QHBoxLayout()
        s_layout.addWidget(QLabel(TRANSLATIONS[self.current_lang]['mode']))
        self.mode_combo = QComboBox(); self.mode_combo.addItems(["Локально", "Облако"]); s_layout.addWidget(self.mode_combo)
        s_layout.addWidget(QLabel(TRANSLATIONS[self.current_lang]['type']))
        self.type_combo = QComboBox(); self.type_combo.addItems(["Базовый", "Premium", "Enterprise"])
        self.type_combo.currentTextChanged.connect(self._check_license); s_layout.addWidget(self.type_combo)
        s_layout.addWidget(QLabel(TRANSLATIONS[self.current_lang]['lang']))
        self.lang_combo = QComboBox(); self.lang_combo.addItems(["Русский", "English"])
        self.lang_combo.currentTextChanged.connect(self._change_language); s_layout.addWidget(self.lang_combo)
        self.rule_btn = QPushButton(TRANSLATIONS[self.current_lang]['rules'])
        self.rule_btn.clicked.connect(self._open_rule_manager); s_layout.addWidget(self.rule_btn)
        self.upgrade_btn = QPushButton("💎 Upgrade")
        self.upgrade_btn.setStyleSheet("background-color: #e94560;")
        self.upgrade_btn.clicked.connect(self._open_purchase_dialog); s_layout.addWidget(self.upgrade_btn)
        self.start_btn = QPushButton(TRANSLATIONS[self.current_lang]['start'])
        self.start_btn.setObjectName("startBtn"); self.start_btn.clicked.connect(self.start_scan); s_layout.addWidget(self.start_btn)
        layout.addLayout(s_layout)
        self.progress = QProgressBar(); self.progress.setFormat("Ready"); layout.addWidget(self.progress)
        self.tabs = QTabWidget()
        res_tab = QWidget(); r_layout = QVBoxLayout(res_tab)
        self.results_table = QTableWidget(); self.results_table.setColumnCount(4); self._update_table_headers()
        self.results_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        r_layout.addWidget(self.results_table)
        export_layout = QHBoxLayout()
        self.export_csv_btn = QPushButton("📄 CSV"); self.export_csv_btn.clicked.connect(self.export_csv); export_layout.addWidget(self.export_csv_btn)
        self.export_html_btn = QPushButton("🌐 HTML"); self.export_html_btn.clicked.connect(self.export_html); export_layout.addWidget(self.export_html_btn)
        self.export_pdf_btn = QPushButton("📑 PDF"); self.export_pdf_btn.clicked.connect(self.export_pdf); export_layout.addWidget(self.export_pdf_btn)
        r_layout.addLayout(export_layout)
        self.tabs.addTab(res_tab, TRANSLATIONS[self.current_lang]['res_tab'])
        log_tab = QWidget(); l_layout = QVBoxLayout(log_tab)
        self.log_text = QTextEdit(); self.log_text.setReadOnly(True); l_layout.addWidget(self.log_text)
        self.tabs.addTab(log_tab, TRANSLATIONS[self.current_lang]['log_tab'])
        layout.addWidget(self.tabs, 1)
        self.status_label = QLabel("Ready"); self.status_label.setStyleSheet("color: #2ecc71;"); layout.addWidget(self.status_label)

    def _update_table_headers(self):
        t = TRANSLATIONS[self.current_lang]
        self.results_table.setHorizontalHeaderLabels([t['col_id'], t['col_sev'], t['col_desc'], t['col_fix']])

    def _check_license(self, text):
        if text in ["Premium", "Enterprise"] and not self.settings.get('license_key'):
            self._open_purchase_dialog()

    def _change_language(self, text):
        self.current_lang = 'ru' if text == 'Русский' else 'en'
        self.settings['language'] = self.current_lang; save_settings(self.settings)
        t = TRANSLATIONS[self.current_lang]
        self.setWindowTitle(t['title']); self._update_table_headers()
        self.tabs.setTabText(0, t['res_tab']); self.tabs.setTabText(1, t['log_tab'])
        self.start_btn.setText(t['start']); self.rule_btn.setText(t['rules'])

    def _open_rule_manager(self):
        if self.type_combo.currentText() == "Базовый":
            QMessageBox.warning(self, "License Required", "Rule Manager available only in Premium/Enterprise.")
            return
        RuleManager(self).exec_()

    def _open_purchase_dialog(self):
        dialog = PurchaseDialog(self)
        if dialog.exec_() == PurchaseDialog.Accepted:
            QMessageBox.information(self, "✅ Success", "License activated! Premium/Enterprise features available.")
            try:
                with open('license.key', 'r') as f:
                    self.settings['license_key'] = f.read().strip()
                    save_settings(self.settings)
            except: pass

    def start_scan(self):
        target = self.target_input.text().strip()
        if not target: return QMessageBox.warning(self, "Warning", "Enter URL!")
        self.settings['target'] = target
        self.settings['scan_type'] = {'Базовый': 'basic', 'Premium': 'premium', 'Enterprise': 'enterprise'}.get(self.type_combo.currentText(), 'basic')
        save_settings(self.settings)
        self.start_btn.setEnabled(False); self.progress.setFormat("⏳ Scanning...")
        self.results_table.setRowCount(0); self.log_text.clear()
        self.worker = ScanWorker(target, 'local', self.settings['scan_type'], license_key=self.settings.get('license_key', ''))
        self.worker.log_signal.connect(self.log_text.append)
        self.worker.result_signal.connect(self.on_results)
        self.worker.error_signal.connect(lambda e: self.status_label.setText(f"❌ {e}"))
        self.worker.finished_signal.connect(lambda: self.start_btn.setEnabled(True))
        self.worker.start()

    def on_results(self, results: list):
        self.last_results = results
        self.progress.setFormat(f"✅ Found: {len(results)}")
        self.results_table.setRowCount(len(results))
        for row, item in enumerate(results):
            self.results_table.setItem(row, 0, QTableWidgetItem(str(item.get('id', row+1))))
            self.results_table.setCellWidget(row, 1, SeverityBadge(item.get('severity', 'unknown')))
            self.results_table.setItem(row, 2, QTableWidgetItem(item.get('description', '')))
            self.results_table.setItem(row, 3, QTableWidgetItem(item.get('remediation', '')))
        self.results_table.resizeRowsToContents()

    def _get_results_from_table(self):
        results = []
        for row in range(self.results_table.rowCount()):
            results.append({
                'id': self.results_table.item(row, 0).text() if self.results_table.item(row, 0) else '',
                'severity': self.results_table.cellWidget(row, 1).severity if self.results_table.cellWidget(row, 1) else '',
                'description': self.results_table.item(row, 2).text() if self.results_table.item(row, 2) else '',
                'remediation': self.results_table.item(row, 3).text() if self.results_table.item(row, 3) else '',
                'endpoint': ''
            })
        return results

    def export_csv(self):
        if self.results_table.rowCount() == 0: return QMessageBox.warning(self, "No Data", "No results")
        filename, _ = QFileDialog.getSaveFileName(self, "Save CSV", "", "CSV (*.csv)")
        if filename:
            results = self._get_results_from_table()
            try:
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['ID', 'Severity', 'Description', 'How to Fix'])
                    for item in results:
                        writer.writerow([item['id'], item['severity'], item['description'], item['remediation']])
                QMessageBox.information(self, "Export", f"CSV saved: {filename}")
            except Exception as e: QMessageBox.critical(self, "Error", f"Failed: {e}")

    def export_html(self):
        if self.results_table.rowCount() == 0: return QMessageBox.warning(self, "No Data", "No results")
        filename, _ = QFileDialog.getSaveFileName(self, "Save HTML", "", "HTML (*.html)")
        if filename:
            results = self._get_results_from_table()
            try:
                severity_colors = {'critical': '#9b59b6', 'high': '#e74c3c', 'medium': '#f39c12', 'low': '#3498db'}
                date_str = datetime.now().strftime("%d.%m.%Y %H:%M")
                html_content = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>API Security Report</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }}
.container {{ max-width: 1200px; margin: 0 auto; background: #fef9e7; padding: 40px; border-radius: 12px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); }}
h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 15px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 30px; background: white; }}
th, td {{ padding: 14px; text-align: left; border: 1px solid #ddd; }}
th {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }}
tr:nth-child(even) {{ background: #f8f9fa; }}
.severity {{ padding: 6px 14px; border-radius: 20px; color: white; font-weight: bold; display: inline-block; text-transform: uppercase; font-size: 12px; }}
.summary {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; border-radius: 8px; margin: 25px 0; }}
</style></head><body><div class="container">
<h1>🛡️ API Security Report</h1>
<p><strong>Date:</strong> {date_str} | <strong>Total:</strong> {len(results)}</p>
<div class="summary"><h3>📊 Scan Summary</h3>
<p>🔴 Critical: {sum(1 for r in results if r.get('severity') == 'critical')} | 🟠 High: {sum(1 for r in results if r.get('severity') == 'high')} | 🟡 Medium: {sum(1 for r in results if r.get('severity') == 'medium')} | 🔵 Low: {sum(1 for r in results if r.get('severity') == 'low')}</p></div>
<table><tr><th>ID</th><th>Severity</th><th>Description</th></tr>"""
                for item in results:
                    sev = item.get('severity', 'unknown').lower()
                    color = severity_colors.get(sev, '#95a5a6')
                    html_content += f"""<tr><td>{html.escape(str(item.get('id', '')))}</td>
<td><span class="severity" style="background: {color}">{html.escape(sev.upper())}</span></td>
<td>{html.escape(item.get('description', ''))}<br><br><strong>Recommendation:</strong> {html.escape(item.get('remediation', ''))}</td></tr>"""
                html_content += "</table></div></body></html>"
                with open(filename, 'w', encoding='utf-8') as f: f.write(html_content)
                QMessageBox.information(self, "Export", f"HTML saved: {filename}")
            except Exception as e: QMessageBox.critical(self, "Error", f"Failed: {e}")

    def export_pdf(self):
        if self.results_table.rowCount() == 0: return QMessageBox.warning(self, "No Data", "No results")
        filename, _ = QFileDialog.getSaveFileName(self, "Save PDF", "", "PDF (*.pdf)")
        if filename:
            results = self._get_results_from_table()
            try:
                from reportlab.lib.pagesizes import A4
                from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
                from reportlab.lib import colors
                from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
                from reportlab.pdfbase import pdfmetrics
                from reportlab.pdfbase.ttfonts import TTFont
                from reportlab.lib.units import inch
                
                font_paths = [
                    os.path.join(os.path.dirname(__file__), 'resources', 'DejaVuSans.ttf'),
                    '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
                    '/System/Library/Fonts/Supplemental/Arial.ttf'
                ]
                font_registered = False
                for fp in font_paths:
                    try:
                        if os.path.exists(fp):
                            pdfmetrics.registerFont(TTFont('CyrillicFont', fp))
                            font_registered = True; break
                    except: continue
                
                doc = SimpleDocTemplate(filename, pagesize=A4, topMargin=0.6*inch, bottomMargin=0.6*inch, leftMargin=0.4*inch, rightMargin=0.4*inch)
                elements = []
                
                if font_registered:
                    title_style = ParagraphStyle('Title', fontName='CyrillicFont', fontSize=16, textColor=colors.HexColor('#2c3e50'), spaceAfter=10, alignment=1)
                    heading_style = ParagraphStyle('Heading', fontName='CyrillicFont', fontSize=11, textColor=colors.HexColor('#34495e'), spaceAfter=8, spaceBefore=10)
                    normal_style = ParagraphStyle('Normal', fontName='CyrillicFont', fontSize=8, textColor=colors.HexColor('#34495e'), leading=10)
                    tf = 'CyrillicFont'
                else:
                    title_style = ParagraphStyle('Title', fontSize=16, textColor=colors.black, spaceAfter=10, alignment=1)
                    heading_style = ParagraphStyle('Heading', fontSize=11, textColor=colors.black, spaceAfter=8)
                    normal_style = ParagraphStyle('Normal', fontSize=8, textColor=colors.black, leading=10)
                    tf = 'Helvetica'
                
                elements.append(Paragraph("API Security Scanner Pro", title_style))
                elements.append(Paragraph("Security Audit Report", heading_style))
                elements.append(Spacer(1, 8))
                date_str = datetime.now().strftime("%d.%m.%Y %H:%M")
                elements.append(Paragraph(f"<b>Date:</b> {date_str} | <b>Total:</b> {len(results)}", normal_style))
                elements.append(Spacer(1, 12))
                
                critical = sum(1 for r in results if r.get('severity') == 'critical')
                high = sum(1 for r in results if r.get('severity') == 'high')
                medium = sum(1 for r in results if r.get('severity') == 'medium')
                low = sum(1 for r in results if r.get('severity') == 'low')
                
                elements.append(Paragraph("Scan Summary", heading_style))
                stats_data = [['Critical', str(critical)], ['High', str(high)], ['Medium', str(medium)], ['Low', str(low)]]
                stats_table = Table(stats_data, colWidths=[120, 60])
                stats_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#3498db')),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, -1), tf), ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('GRID', (0, 0), (-1, -1), 1, colors.white),
                    ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor('#3498db'), colors.HexColor('#2980b9')]),
                    ('TOPPADDING', (0, 0), (-1, -1), 6), ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ]))
                elements.append(stats_table)
                elements.append(Spacer(1, 15))
                elements.append(Paragraph("Vulnerabilities List", heading_style))
                
                data = [['ID', 'Severity', 'Description']]
                for item in results:
                    desc = item.get('description', '')
                    rem = item.get('remediation', '')
                    full = Paragraph(f"{desc}<br/><br/><b>Recommendation:</b> {rem}" if rem else desc, normal_style)
                    data.append([str(item.get('id', '')), item.get('severity', '').upper(), full])
                
                # Увеличенная ширина ID (100) и описания (340), чтобы текст не налезал
                table = Table(data, colWidths=[100, 80, 340])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), tf), ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'), ('VALIGN', (0, 0), (-1, 0), 'MIDDLE'),
                    ('FONTNAME', (0, 1), (-1, -1), tf), ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fef9e7')]),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6), ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 8), ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ]))
                elements.append(table)
                doc.build(elements)
                QMessageBox.information(self, "Export", f"PDF saved: {filename}")
            except ImportError: QMessageBox.warning(self, "Missing", "Install reportlab: pip install reportlab")
            except Exception as e: QMessageBox.critical(self, "Error", f"Failed: {e}")

def run():
    app = QApplication(sys.argv); app.setStyle('Fusion')
    w = MainWindow(); w.show(); sys.exit(app.exec_())

if __name__ == '__main__': run()
