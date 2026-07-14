with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Новый метод с правильными размерами колонок
new_pdf_method = '''    def export_pdf(self):
        if self.results_table.rowCount() == 0: return QMessageBox.warning(self, "No Data", "No results to export")
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
                from datetime import datetime
                import os
                
                # Регистрируем шрифт с кириллицей
                font_registered = False
                font_paths = [
                    os.path.join(os.path.dirname(__file__), 'resources', 'DejaVuSans.ttf'),
                    '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
                    '/System/Library/Fonts/Supplemental/Arial.ttf'
                ]
                
                for font_path in font_paths:
                    try:
                        if os.path.exists(font_path):
                            pdfmetrics.registerFont(TTFont('CyrillicFont', font_path))
                            font_registered = True
                            break
                    except:
                        continue
                
                # Создаем документ с альбомной ориентацией для большего пространства
                doc = SimpleDocTemplate(
                    filename, 
                    pagesize=A4, 
                    topMargin=0.6*inch, 
                    bottomMargin=0.6*inch, 
                    leftMargin=0.4*inch, 
                    rightMargin=0.4*inch
                )
                elements = []
                
                # Определяем стили
                if font_registered:
                    title_style = ParagraphStyle('Title', fontName='CyrillicFont', fontSize=16, textColor=colors.HexColor('#2c3e50'), spaceAfter=10, alignment=1, leading=20)
                    heading_style = ParagraphStyle('Heading', fontName='CyrillicFont', fontSize=11, textColor=colors.HexColor('#34495e'), spaceAfter=8, spaceBefore=10, leading=14)
                    normal_style = ParagraphStyle('Normal', fontName='CyrillicFont', fontSize=8, textColor=colors.HexColor('#34495e'), leading=10)
                    table_font = 'CyrillicFont'
                else:
                    title_style = ParagraphStyle('Title', fontSize=16, textColor=colors.black, spaceAfter=10, alignment=1)
                    heading_style = ParagraphStyle('Heading', fontSize=11, textColor=colors.black, spaceAfter=8)
                    normal_style = ParagraphStyle('Normal', fontSize=8, textColor=colors.black, leading=10)
                    table_font = 'Helvetica'
                
                # Заголовок
                elements.append(Paragraph("API Security Scanner Pro", title_style))
                elements.append(Paragraph("Security Audit Report", heading_style))
                elements.append(Spacer(1, 8))
                
                # Мета-информация
                date_str = datetime.now().strftime("%d.%m.%Y %H:%M")
                elements.append(Paragraph(f"<b>Date:</b> {date_str} | <b>Total vulnerabilities:</b> {len(results)}", normal_style))
                elements.append(Spacer(1, 12))
                
                # Статистика
                critical = sum(1 for r in results if r.get('severity') == 'critical')
                high = sum(1 for r in results if r.get('severity') == 'high')
                medium = sum(1 for r in results if r.get('severity') == 'medium')
                low = sum(1 for r in results if r.get('severity') == 'low')
                
                elements.append(Paragraph("Scan Summary", heading_style))
                
                stats_data = [
                    ['Critical', str(critical)],
                    ['High', str(high)],
                    ['Medium', str(medium)],
                    ['Low', str(low)]
                ]
                
                stats_table = Table(stats_data, colWidths=[120, 60])
                stats_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#3498db')),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, -1), table_font),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('GRID', (0, 0), (-1, -1), 1, colors.white),
                    ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor('#3498db'), colors.HexColor('#2980b9')]),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ]))
                elements.append(stats_table)
                elements.append(Spacer(1, 15))
                
                # Таблица уязвимостей
                elements.append(Paragraph("Vulnerabilities List", heading_style))
                
                # Создаем данные для таблицы с переносом текста через Paragraph
                data = [['ID', 'Severity', 'Description']]
                for item in results:
                    desc = item.get('description', '')
                    remediation = item.get('remediation', '')
                    # Используем Paragraph для автоматического переноса
                    full_desc = Paragraph(f"{desc}\\n\\n<b>Recommendation:</b> {remediation}" if remediation else desc, normal_style)
                    data.append([
                        str(item.get('id', '')),
                        item.get('severity', '').upper(),
                        full_desc
                    ])
                
                # УВЕЛИЧЕННАЯ ширина колонки ID (100pt вместо 70pt)
                # Ширина A4 = 595pt, вычитаем поля (0.4*inch * 2 = 57.6pt) = 537.4pt
                # ID: 100pt, Severity: 70pt, Description: 367.4pt
                table = Table(data, colWidths=[100, 70, 367])
                table.setStyle(TableStyle([
                    # Заголовок
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), table_font),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, 0), 'MIDDLE'),
                    
                    # Данные
                    ('FONTNAME', (0, 1), (-1, -1), table_font),
                    ('FONTSIZE', (0, 1), (-1, -1), 7),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    
                    # Чередование строк
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fef9e7')]),
                    
                    # Увеличенные отступы
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ]))
                
                elements.append(table)
                doc.build(elements)
                QMessageBox.information(self, "Export", f"PDF saved: {filename}")
            except ImportError:
                QMessageBox.warning(self, "Missing Library", "Install reportlab: pip install reportlab")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed: {e}")'''

# Заменяем старый метод
import re
pattern = r'    def export_pdf\(self\):.*?(?=\n    def |\n\ndef |\Z)'
match = re.search(pattern, content, re.DOTALL)
if match:
    content = content[:match.start()] + new_pdf_method + content[match.end():]
    with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("✅ PDF метод обновлён с правильными размерами колонок!")
else:
    print("⚠️ Не удалось найти метод export_pdf")
