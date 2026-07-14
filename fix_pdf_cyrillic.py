with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Новый метод с поддержкой кириллицы и красивым оформлением
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
                
                # Регистрируем шрифт с поддержкой кириллицы
                try:
                    font_path = os.path.join(os.path.dirname(__file__), 'resources', 'DejaVuSans.ttf')
                    pdfmetrics.registerFont(TTFont('DejaVuSans', font_path))
                    font_family = 'DejaVuSans'
                except:
                    # Если шрифт не найден, пробуем системные
                    try:
                        pdfmetrics.registerFont(TTFont('DejaVuSans', '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'))
                        font_family = 'DejaVuSans'
                    except:
                        font_family = 'Helvetica'
                
                doc = SimpleDocTemplate(filename, pagesize=A4, topMargin=0.7*inch, bottomMargin=0.7*inch, leftMargin=0.5*inch, rightMargin=0.5*inch)
                elements = []
                styles = getSampleStyleSheet()
                
                # Кастомные стили с кириллицей
                title_style = ParagraphStyle(
                    'CustomTitle',
                    parent=styles['Title'],
                    fontName=font_family,
                    fontSize=22,
                    textColor=colors.HexColor('#2c3e50'),
                    spaceAfter=20,
                    alignment=1
                )
                
                heading_style = ParagraphStyle(
                    'CustomHeading',
                    parent=styles['Heading2'],
                    fontName=font_family,
                    fontSize=14,
                    textColor=colors.HexColor('#34495e'),
                    spaceAfter=10,
                    spaceBefore=15
                )
                
                normal_style = ParagraphStyle(
                    'CustomNormal',
                    parent=styles['Normal'],
                    fontName=font_family,
                    fontSize=10,
                    textColor=colors.HexColor('#34495e'),
                    leading=14
                )
                
                # Заголовок
                elements.append(Paragraph("🛡️ API Security Scanner Pro", title_style))
                elements.append(Paragraph("Отчёт по безопасности API", heading_style))
                elements.append(Spacer(1, 15))
                
                # Мета-информация
                date_str = datetime.now().strftime("%d.%m.%Y %H:%M")
                elements.append(Paragraph(f"<b>Дата:</b> {date_str}", normal_style))
                elements.append(Paragraph(f"<b>Всего уязвимостей найдено:</b> {len(results)}", normal_style))
                elements.append(Spacer(1, 20))
                
                # Статистика
                critical_count = sum(1 for r in results if r.get('severity') == 'critical')
                high_count = sum(1 for r in results if r.get('severity') == 'high')
                medium_count = sum(1 for r in results if r.get('severity') == 'medium')
                low_count = sum(1 for r in results if r.get('severity') == 'low')
                
                elements.append(Paragraph("📊 Статистика сканирования", heading_style))
                
                stats_data = [
                    ['Критические', str(critical_count), '🔴'],
                    ['Высокие', str(high_count), '🟠'],
                    ['Средние', str(medium_count), '🟡'],
                    ['Низкие', str(low_count), '🔵']
                ]
                
                stats_table = Table(stats_data, colWidths=[120, 80, 60])
                stats_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#3498db')),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, -1), font_family),
                    ('FONTSIZE', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.white),
                    ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor('#3498db'), colors.HexColor('#2980b9')]),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ]))
                elements.append(stats_table)
                elements.append(Spacer(1, 25))
                
                # Таблица уязвимостей
                elements.append(Paragraph("📋 Список обнаруженных уязвимостей:", heading_style))
                
                data = [['ID', 'Уровень', 'Описание и рекомендации']]
                for item in results:
                    desc = item.get('description', '')
                    remediation = item.get('remediation', '')
                    full_desc = f"{desc}\\n\\n<b>Рекомендация:</b> {remediation}" if remediation else desc
                    data.append([
                        str(item.get('id', '')),
                        item.get('severity', '').upper(),
                        full_desc
                    ])
                
                table = Table(data, colWidths=[70, 80, 350])
                table.setStyle(TableStyle([
                    # Заголовок
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), font_family),
                    ('FONTSIZE', (0, 0), (-1, 0), 11),
                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, 0), 'MIDDLE'),
                    
                    # Данные
                    ('FONTNAME', (0, 1), (-1, -1), font_family),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    
                    # Чередование строк
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fef9e7')]),
                    
                    # Отступы
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ]))
                
                elements.append(table)
                
                doc.build(elements)
                QMessageBox.information(self, "Export", f"PDF отчёт сохранён: {filename}")
            except ImportError:
                QMessageBox.warning(self, "Missing Library", "Установите reportlab: pip install reportlab")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Ошибка: {e}")'''

# Заменяем старый метод
import re
pattern = r'    def export_pdf\(self\):.*?(?=\n    def |\n\ndef |\Z)'
match = re.search(pattern, content, re.DOTALL)
if match:
    content = content[:match.start()] + new_pdf_method + content[match.end():]
    with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("✅ PDF export полностью переписан с поддержкой кириллицы!")
else:
    print("⚠️ Не удалось найти метод export_pdf")
