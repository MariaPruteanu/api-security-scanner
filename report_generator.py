import base64
import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import sqlite3
from charts import get_severity_data, generate_severity_pie_chart, generate_severity_bar_chart

class ReportGenerator:
    def __init__(self, scan_id, output_filename="report.pdf"):
        self.scan_id = scan_id
        self.output_filename = output_filename
        self.styles = getSampleStyleSheet()
        self.story = []
        self._init_custom_styles()

    def _init_custom_styles(self):
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=22,
            alignment=TA_CENTER,
            spaceAfter=20,
            textColor=colors.HexColor('#1a237e')
        ))
        self.styles.add(ParagraphStyle(
            name='CustomHeading1',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.HexColor('#283593')
        ))
        self.styles.add(ParagraphStyle(
            name='CustomBodyText',
            parent=self.styles['BodyText'],
            fontSize=11,
            leading=14,
            alignment=TA_LEFT
        ))

    def _get_logo_image(self):
        logo_path = "logo.png"
        if os.path.exists(logo_path):
            try:
                return Image(logo_path, width=2*cm, height=2*cm)
            except:
                pass
        return None

    def _add_title_page(self):
        logo = self._get_logo_image()
        if logo:
            self.story.append(logo)
            self.story.append(Spacer(1, 0.5*cm))
        self.story.append(Paragraph("Отчёт по безопасности API", self.styles['CustomTitle']))
        self.story.append(Spacer(1, 0.5*cm))
        self.story.append(Paragraph(f"Сканирование #{self.scan_id}", self.styles['CustomHeading1']))
        self.story.append(Spacer(1, 0.5*cm))
        self.story.append(Paragraph(f"Дата: {datetime.now().strftime('%d.%m.%Y %H:%M')}", self.styles['CustomBodyText']))
        self.story.append(Spacer(1, 1*cm))
        conn = sqlite3.connect("scanner.db")
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND (name='scan_tasks' OR name='scans' OR name='scan_results')")
        table = c.fetchone()
        info_text = ""
        if table:
            table_name = table[0]
            c.execute(f"SELECT target, status FROM {table_name} WHERE id=?", (self.scan_id,))
            row = c.fetchone()
            if row:
                target, status = row
                info_text = f"Цель: {target or 'не указано'}\nСтатус: {status or 'завершено'}"
        conn.close()
        if info_text:
            self.story.append(Paragraph(info_text, self.styles['CustomBodyText']))
        self.story.append(PageBreak())

    def _add_table_of_contents(self):
        self.story.append(Paragraph("Содержание", self.styles['CustomHeading1']))
        items = ["1. Общая информация", "2. Статистика уязвимостей", "3. Детальный список уязвимостей", "4. Рекомендации"]
        for item in items:
            self.story.append(Paragraph(item, self.styles['CustomBodyText']))
            self.story.append(Spacer(1, 0.2*cm))
        self.story.append(PageBreak())

    def _add_charts(self):
        severity_data = get_severity_data(self.scan_id)
        if not severity_data:
            self.story.append(Paragraph("Нет данных для построения графиков", self.styles['CustomBodyText']))
            return
        pie_b64 = generate_severity_pie_chart(severity_data, 'base64')
        if pie_b64:
            pie_path = "/tmp/pie_chart.png"
            with open(pie_path, "wb") as f:
                f.write(base64.b64decode(pie_b64))
            img_pie = Image(pie_path, width=12*cm, height=8*cm)
            self.story.append(Paragraph("Распределение по критичности", self.styles['CustomHeading1']))
            self.story.append(img_pie)
            self.story.append(Spacer(1, 0.5*cm))
        bar_b64 = generate_severity_bar_chart(severity_data, 'base64')
        if bar_b64:
            bar_path = "/tmp/bar_chart.png"
            with open(bar_path, "wb") as f:
                f.write(base64.b64decode(bar_b64))
            img_bar = Image(bar_path, width=12*cm, height=8*cm)
            self.story.append(Paragraph("Количество уязвимостей по критичности", self.styles['CustomHeading1']))
            self.story.append(img_bar)
            self.story.append(Spacer(1, 0.5*cm))

    def _add_vulnerabilities_table(self):
        conn = sqlite3.connect("scanner.db")
        c = conn.cursor()
        tables = c.execute("SELECT name FROM sqlite_master WHERE type='table' AND (name='vulnerabilities' OR name='vulns' OR name='issues')").fetchall()
        if not tables:
            self.story.append(Paragraph("Таблица уязвимостей не найдена", self.styles['CustomBodyText']))
            conn.close()
            return
        table_name = tables[0][0]
        c.execute(f"PRAGMA table_info({table_name})")
        columns = [col[1] for col in c.fetchall()]
        if 'scan_id' in columns:
            c.execute(f"SELECT id, name, severity, description FROM {table_name} WHERE scan_id=?", (self.scan_id,))
        else:
            c.execute(f"SELECT id, name, severity, description FROM {table_name}")
        rows = c.fetchall()
        conn.close()
        if not rows:
            self.story.append(Paragraph("Уязвимостей не обнаружено", self.styles['CustomBodyText']))
            return
        self.story.append(Paragraph("Детальный список уязвимостей", self.styles['CustomHeading1']))
        data = [["ID", "Название", "Severity", "Описание"]]
        for row in rows:
            data.append([str(row[0]), row[1] or "—", row[2] or "unknown", (row[3] or "")[:50] + "..."])
        table = Table(data, colWidths=[1*cm, 3*cm, 2*cm, 9*cm])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#283593')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('BACKGROUND', (0,1), (-1,-1), colors.beige),
            ('GRID', (0,0), (-1,-1), 1, colors.grey),
            ('WORD_WRAP', (0,0), (-1,-1), True),
        ]))
        self.story.append(table)

    def _add_recommendations(self):
        self.story.append(Paragraph("Рекомендации по исправлению", self.styles['CustomHeading1']))
        rec_text = "Общие рекомендации:\n• Регулярно обновляйте зависимости и библиотеки.\n• Используйте аутентификацию и авторизацию для всех эндпоинтов.\n• Применяйте валидацию входных данных.\n• Настройте CORS политики.\n• Внедрите мониторинг и логирование."
        self.story.append(Paragraph(rec_text, self.styles['CustomBodyText']))

    def generate(self):
        self._add_title_page()
        self._add_table_of_contents()
        self._add_charts()
        self._add_vulnerabilities_table()
        self._add_recommendations()
        doc = SimpleDocTemplate(self.output_filename, pagesize=A4,
                                leftMargin=2*cm, rightMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)
        doc.build(self.story)
        print(f"✅ Отчёт сохранён: {self.output_filename}")
