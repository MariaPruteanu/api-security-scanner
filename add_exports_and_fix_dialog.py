import os

# Добавляем необходимые импорты
with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Добавляем импорты для экспорта если их нет
if 'from reportlab' not in content:
    content = content.replace(
        'from PyQt5.QtGui import QFont',
        'from PyQt5.QtGui import QFont\nimport csv\nimport html'
    )
    print("✅ Добавлены импорты для экспорта")

# 2. Проверяем и исправляем LicenseDialog
if 'class LicenseDialog' in content:
    # Ищем где начинается класс и полностью переписываем его
    import re
    
    new_dialog = '''class LicenseDialog(QDialog):
    def __init__(self, license_type="Premium", parent=None):
        super().__init__(parent)
        self.license_type = license_type
        
        if license_type == "Enterprise":
            self.setWindowTitle("🚀 Enterprise License")
            title = "🚀 Enterprise Edition"
            features = "✓ All 49+ security rules\\n✓ Rule Manager\\n✓ PDF/JSON/CSV Export\\n✓ Priority Support\\n✓ Custom Rules\\n✓ API Access"
            color = "#9b59b6"
        else:
            self.setWindowTitle("⭐ Premium License")
            title = "⭐ Premium Edition"
            features = "✓ All 49 security rules\\n✓ Rule Manager\\n✓ Advanced Reports"
            color = "#f39c12"
        
        self.setMinimumSize(500, 300 if license_type == "Enterprise" else 260)
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        
        title_label = QLabel(title)
        title_label.setFont(QFont("Arial", 14, QFont.Bold))
        title_label.setStyleSheet(f"color: {color}; font-size: 16px;")
        layout.addWidget(title_label)
        
        desc = QLabel(f"\\n{features}\\n\\nEnter license key:")
        desc.setStyleSheet("color: #e0e0e0; font-size: 13px;")
        layout.addWidget(desc)
        
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText(f"{license_type.upper()}-XXXX-XXXX-XXXX")
        self.key_input.setStyleSheet("padding: 8px; font-size: 14px;")
        layout.addWidget(self.key_input)
        
        btn_layout = QHBoxLayout()
        ok_btn = QPushButton(f"✅ Activate {license_type}")
        ok_btn.setStyleSheet(f"background-color: {color}; padding: 10px; font-weight: bold;")
        ok_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("❌ Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(ok_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
    
    def get_key(self):
        return self.key_input.text().strip()

'''
    
    # Заменяем весь старый класс на новый
    pattern = r'class LicenseDialog\(QDialog\):.*?(?=\nclass |\Z)'
    content = re.sub(pattern, new_dialog, content, flags=re.DOTALL)
    print("✅ LicenseDialog полностью переписан")

# 3. Добавляем методы экспорта перед классом MainWindow или в него
export_methods = '''
    def export_to_csv(self, results, filename):
        """Экспорт в CSV"""
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['ID', 'Severity', 'Description', 'How to Fix', 'Endpoint'])
                for item in results:
                    writer.writerow([
                        item.get('id', ''),
                        item.get('severity', ''),
                        item.get('description', ''),
                        item.get('remediation', ''),
                        item.get('endpoint', '')
                    ])
            QMessageBox.information(self, "Экспорт", f"Отчёт сохранён: {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось экспортировать: {e}")
    
    def export_to_html(self, results, filename):
        """Экспорт в HTML"""
        try:
            severity_colors = {'critical': '#9b59b6', 'high': '#e74c3c', 'medium': '#f39c12', 'low': '#3498db'}
            
            html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>API Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #e94560; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #1a1a2e; color: white; }}
        .severity {{ padding: 4px 12px; border-radius: 4px; color: white; font-weight: bold; display: inline-block; }}
        .summary {{ background: #16213e; color: white; padding: 20px; border-radius: 6px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ API Security Scanner Pro - Report</h1>
        <div class="summary">
            <h3>Scan Summary</h3>
            <p>Total vulnerabilities found: <strong>{len(results)}</strong></p>
            <p>Critical: {sum(1 for r in results if r.get('severity') == 'critical')}</p>
            <p>High: {sum(1 for r in results if r.get('severity') == 'high')}</p>
            <p>Medium: {sum(1 for r in results if r.get('severity') == 'medium')}</p>
        </div>
        <table>
            <tr><th>ID</th><th>Severity</th><th>Description</th><th>How to Fix</th></tr>
'''
            for item in results:
                sev = item.get('severity', 'unknown').lower()
                color = severity_colors.get(sev, '#95a5a6')
                html_content += f"""            <tr>
                <td>{html.escape(str(item.get('id', '')))}</td>
                <td><span class="severity" style="background: {color}">{html.escape(sev.upper())}</span></td>
                <td>{html.escape(item.get('description', ''))}</td>
                <td>{html.escape(item.get('remediation', ''))}</td>
            </tr>
"""
            html_content += """        </table>
    </div>
</body>
</html>"""
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            QMessageBox.information(self, "Export", f"HTML report saved: {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export HTML: {e}")
    
    def export_to_pdf(self, results, filename):
        """Экспорт в PDF (упрощённый)"""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet
            
            doc = SimpleDocTemplate(filename, pagesize=A4)
            elements = []
            styles = getSampleStyleSheet()
            
            elements.append(Paragraph("🛡️ API Security Scanner Pro - Report", styles['Title']))
            elements.append(Spacer(1, 20))
            elements.append(Paragraph(f"Total vulnerabilities: {len(results)}", styles['Normal']))
            elements.append(Spacer(1, 20))
            
            data = [['ID', 'Severity', 'Description', 'How to Fix']]
            for item in results:
                data.append([
                    str(item.get('id', '')),
                    item.get('severity', '').upper(),
                    item.get('description', '')[:50],
                    item.get('remediation', '')[:50]
                ])
            
            table = Table(data, colWidths=[50, 80, 200, 200])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
            ]))
            elements.append(table)
            
            doc.build(elements)
            QMessageBox.information(self, "Export", f"PDF report saved: {filename}")
        except ImportError:
            QMessageBox.warning(self, "Missing Library", "Please install reportlab: pip install reportlab")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export PDF: {e}")

'''

# Вставляем методы экспорта перед методом start_scan
if 'def export_to_csv' not in content:
    content = content.replace('    def start_scan', export_methods + '    def start_scan')
    print("✅ Добавлены методы экспорта (CSV, HTML, PDF)")

# 4. Добавляем кнопки экспорта в интерфейс
if 'export_csv_btn' not in content:
    # Находим где заканчивается создание таблицы результатов и добавляем кнопки
    old_table = '''        r_layout.addWidget(self.results_table)
        self.tabs.addTab(res_tab, TRANSLATIONS[self.current_lang]['res_tab'])'''
    
    new_table = '''        r_layout.addWidget(self.results_table)
        
        # Кнопки экспорта
        export_layout = QHBoxLayout()
        self.export_csv_btn = QPushButton("📄 Export CSV")
        self.export_csv_btn.clicked.connect(self.export_csv)
        export_layout.addWidget(self.export_csv_btn)
        
        self.export_html_btn = QPushButton("🌐 Export HTML")
        self.export_html_btn.clicked.connect(self.export_html)
        export_layout.addWidget(self.export_html_btn)
        
        self.export_pdf_btn = QPushButton("📑 Export PDF")
        self.export_pdf_btn.clicked.connect(self.export_pdf)
        export_layout.addWidget(self.export_pdf_btn)
        
        r_layout.addLayout(export_layout)
        self.tabs.addTab(res_tab, TRANSLATIONS[self.current_lang]['res_tab'])'''
    
    content = content.replace(old_table, new_table)
    print("✅ Добавлены кнопки экспорта")

# 5. Добавляем методы-обёртки для кнопок экспорта
if 'def export_csv' not in content or 'def export_csv(self)' not in content:
    export_wrappers = '''
    def export_csv(self):
        if self.results_table.rowCount() == 0:
            return QMessageBox.warning(self, "No Data", "No results to export")
        filename, _ = QFileDialog.getSaveFileName(self, "Save CSV", "", "CSV (*.csv)")
        if filename:
            results = []
            for row in range(self.results_table.rowCount()):
                results.append({
                    'id': self.results_table.item(row, 0).text() if self.results_table.item(row, 0) else '',
                    'severity': self.results_table.cellWidget(row, 1).severity if self.results_table.cellWidget(row, 1) else '',
                    'description': self.results_table.item(row, 2).text() if self.results_table.item(row, 2) else '',
                    'remediation': self.results_table.item(row, 3).text() if self.results_table.item(row, 3) else '',
                    'endpoint': ''
                })
            self.export_to_csv(results, filename)
    
    def export_html(self):
        if self.results_table.rowCount() == 0:
            return QMessageBox.warning(self, "No Data", "No results to export")
        filename, _ = QFileDialog.getSaveFileName(self, "Save HTML", "", "HTML (*.html)")
        if filename:
            results = []
            for row in range(self.results_table.rowCount()):
                results.append({
                    'id': self.results_table.item(row, 0).text() if self.results_table.item(row, 0) else '',
                    'severity': self.results_table.cellWidget(row, 1).severity if self.results_table.cellWidget(row, 1) else '',
                    'description': self.results_table.item(row, 2).text() if self.results_table.item(row, 2) else '',
                    'remediation': self.results_table.item(row, 3).text() if self.results_table.item(row, 3) else '',
                    'endpoint': ''
                })
            self.export_to_html(results, filename)
    
    def export_pdf(self):
        if self.results_table.rowCount() == 0:
            return QMessageBox.warning(self, "No Data", "No results to export")
        filename, _ = QFileDialog.getSaveFileName(self, "Save PDF", "", "PDF (*.pdf)")
        if filename:
            results = []
            for row in range(self.results_table.rowCount()):
                results.append({
                    'id': self.results_table.item(row, 0).text() if self.results_table.item(row, 0) else '',
                    'severity': self.results_table.cellWidget(row, 1).severity if self.results_table.cellWidget(row, 1) else '',
                    'description': self.results_table.item(row, 2).text() if self.results_table.item(row, 2) else '',
                    'remediation': self.results_table.item(row, 3).text() if self.results_table.item(row, 3) else '',
                    'endpoint': ''
                })
            self.export_to_pdf(results, filename)

'''
    content = content.replace('    def on_results', export_wrappers + '    def on_results')
    print("✅ Добавлены обработчики кнопок экспорта")

with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("\\n✅✅✅ Все улучшения добавлены!")
print("  ✓ Исправлен диалог лицензии (Premium/Enterprise)")
print("  ✓ Добавлен экспорт в CSV")
print("  ✓ Добавлен экспорт в HTML")
print("  ✓ Добавлен экспорт в PDF (требуется reportlab)")
