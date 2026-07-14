with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Новый метод с правильными отступами и переносом текста
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
                from reportlab.pdfbase import pdfmetrics
                from reportlab.pdfbase.ttfonts import TTFont
                from reportlab.lib.units import inch, mm
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
                
                # Создаем документ с большими полями
                doc = SimpleDocTemplate(
                    filename, 
                    pagesize=A4, 
                    topMargin=0.8*inch, 
                    bottomMargin=0.8*inch, 
                    leftMargin=0.6*inch, 
                    rightMargin=0.6*inch
                )
                elements = []
                
                # Определяем стили
                if font_registered:
                    title_style = ParagraphStyle('Title', fontName='CyrillicFont', fontSize=18, textColor=colors.HexColor('#2c3e50'), spaceAfter=15, alignment=1, leading=22)
                    heading_style = ParagraphStyle('Heading', fontName='CyrillicFont', fontSize=12, textColor=colors.HexColor('#34495e'), spaceAfter=8, spaceBefore=12, leading=16)
                    normal_style = ParagraphStyle('Normal', fontName='CyrillicFont', fontSize=9, textColor=colors.HexColor('#34495e'), leading=12)
                    table_font = 'CyrillicFont'
                else:
                    title_style = ParagraphStyle('Title', fontSize=18, textColor=colors.black, spaceAfter=15, alignment=1)
                    heading_style = ParagraphStyle('Heading', fontSize=12, textColor=colors.black, spaceAfter=8)
                    normal_style = ParagraphStyle('Normal', fontSize=9, textColor=colors.black, leading=12)
                    table_font = 'Helvetica'
                
                # Заголовок
                elements.append(Paragraph("API Security Scanner Pro", title_style))
                elements.append(Paragraph("Security Audit Report", heading_style))
                elements.append(Spacer(1, 10))
                
                # Мета-информация
                date_str = datetime.now().strftime("%d.%m.%Y %H:%M")
                elements.append(Paragraph(f"<b>Date:</b> {date_str}", normal_style))
                elements.append(Paragraph(f"<b>Total vulnerabilities:</b> {len(results)}", normal_style))
                elements.append(Spacer(1, 15))
                
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
                
                stats_table = Table(stats_data, colWidths=[150, 80])
                stats_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#3498db')),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, -1), table_font),
                    ('FONTSIZE', (0, 0), (-1, -1), 11),
                    ('GRID', (0, 0), (-1, -1), 1, colors.white),
                    ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor('#3498db'), colors.HexColor('#2980b9')]),
                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ]))
                elements.append(stats_table)
                elements.append(Spacer(1, 20))
                
                # Таблица уязвимостей
                elements.append(Paragraph("Vulnerabilities List", heading_style))
                
                # Создаем данные для таблицы с переносом текста
                data = [['ID', 'Severity', 'Description']]
                for item in results:
                    desc = item.get('description', '')
                    remediation = item.get('remediation', '')
                    # Форматируем описание с переносом
                    full_desc = f"{desc}\\n\\nRecommendation:\\n{remediation}" if remediation else desc
                    data.append([
                        str(item.get('id', '')),
                        item.get('severity', '').upper(),
                        full_desc
                    ])
                
                # Создаем таблицу с правильными размерами
                table = Table(data, colWidths=[70, 70, 360])
                table.setStyle(TableStyle([
                    # Заголовок
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), table_font),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, 0), 'MIDDLE'),
                    
                    # Данные
                    ('FONTNAME', (0, 1), (-1, -1), table_font),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    
                    # Чередование строк
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fef9e7')]),
                    
                    # ВАЖНО: Увеличиваем отступы для предотвращения наложения
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                    
                    # Минимальная высота строки
                    ('MINROWHEIGHT', (0, 0), (-1, -1), 30),
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
    print("✅ PDF метод обновлён с правильными отступами!")
else:
    print("⚠️ Не удалось найти метод export_pdf")
