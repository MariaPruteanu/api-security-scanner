with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Находим старый метод export_pdf и заменяем его
import re

# Новый красивый метод export_pdf
new_pdf_method = '''    def export_pdf(self):
        if self.results_table.rowCount() == 0: return QMessageBox.warning(self, "No Data", "No results to export")
        filename, _ = QFileDialog.getSaveFileName(self, "Save PDF", "", "PDF (*.pdf)")
        if filename:
            results = self._get_results_from_table()
            try:
                from reportlab.lib.pagesizes import A4
                from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
                from reportlab.lib import colors
                from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
                from reportlab.lib.units import inch
                from datetime import datetime
                
                doc = SimpleDocTemplate(filename, pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)
                elements = []
                styles = getSampleStyleSheet()
                
                # Кастомные стили
                title_style = ParagraphStyle(
                    'CustomTitle',
                    parent=styles['Title'],
                    fontSize=20,
                    textColor=colors.HexColor('#2c3e50'),
                    spaceAfter=20,
                    alignment=1
                )
                
                heading_style = ParagraphStyle(
                    'CustomHeading',
                    parent=styles['Heading2'],
                    fontSize=14,
                    textColor=colors.HexColor('#34495e'),
                    spaceAfter=10,
                    spaceBefore=15
                )
                
                normal_style = ParagraphStyle(
                    'CustomNormal',
                    parent=styles['Normal'],
                    fontSize=10,
                    textColor=colors.HexColor('#34495e')
                )
                
                # Заголовок
                elements.append(Paragraph("🛡️ API Security Scanner Pro", title_style))
                elements.append(Paragraph("Security Audit Report", heading_style))
                elements.append(Spacer(1, 10))
                
                # Мета-информация
                date_str = datetime.now().strftime("%d.%m.%Y %H:%M")
                elements.append(Paragraph(f"<b>Date:</b> {date_str}", normal_style))
                elements.append(Paragraph(f"<b>Total vulnerabilities found:</b> {len(results)}", normal_style))
                elements.append(Spacer(1, 20))
                
                # Статистика
                critical_count = sum(1 for r in results if r.get('severity') == 'critical')
                high_count = sum(1 for r in results if r.get('severity') == 'high')
                medium_count = sum(1 for r in results if r.get('severity') == 'medium')
                low_count = sum(1 for r in results if r.get('severity') == 'low')
                
                elements.append(Paragraph("📊 Scan Summary", heading_style))
                
                stats_data = [
                    ['Critical', str(critical_count), '🔴'],
                    ['High', str(high_count), '🟠'],
                    ['Medium', str(medium_count), '🟡'],
                    ['Low', str(low_count), '🔵']
                ]
                
                stats_table = Table(stats_data, colWidths=[100, 80, 50])
                stats_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#3498db')),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.white),
                    ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor('#3498db'), colors.HexColor('#2980b9')]),
                ]))
                elements.append(stats_table)
                elements.append(Spacer(1, 20))
                
                # Таблица уязвимостей
                elements.append(Paragraph("List of found vulnerabilities:", heading_style))
                
                data = [['ID', 'Severity', 'Description']]
                for item in results:
                    desc = item.get('description', '')
                    remediation = item.get('remediation', '')
                    full_desc = f"{desc}\\n\\nRecommendation: {remediation}" if remediation else desc
                    data.append([
                        str(item.get('id', '')),
                        item.get('severity', '').upper(),
                        full_desc
                    ])
                
                table = Table(data, colWidths=[80, 80, 340])
                table.setStyle(TableStyle([
                    # Заголовок
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                    
                    # Данные
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    
                    # Чередование строк
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fef9e7')]),
                    
                    # Цвета для severity
                    ('TEXTCOLOR', (1, 1), (1, -1), colors.HexColor('#e74c3c')),
                ]))
                
                elements.append(table)
                
                doc.build(elements)
                QMessageBox.information(self, "Export", f"Beautiful PDF report saved: {filename}")
            except ImportError:
                QMessageBox.warning(self, "Missing Library", "Please install reportlab: pip install reportlab")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed: {e}")'''

# Находим старый метод и заменяем
pattern = r'    def export_pdf\(self\):.*?(?=\n    def |\n\ndef |\Z)'
match = re.search(pattern, content, re.DOTALL)
if match:
    content = content[:match.start()] + new_pdf_method + content[match.end():]
    with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("✅ PDF export метод полностью переписан с красивым оформлением!")
else:
    print("⚠️ Не удалось найти метод export_pdf")
