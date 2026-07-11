import os
import sqlite3
import datetime
import io
import base64
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, 
                                Table, TableStyle, Image, PageBreak)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch, cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import matplotlib.pyplot as plt

class AdvancedReportGenerator:
    def __init__(self, db_path, logo_path=None):
        self.db_path = db_path
        self.logo_path = logo_path if logo_path and os.path.exists(logo_path) else None

        # Регистрируем шрифт для кириллицы (если есть)
        font_path = "/System/Library/Fonts/Supplemental/Arial.ttf"
        if os.path.exists(font_path):
            pdfmetrics.registerFont(TTFont('DejaVuSans', font_path))
            self.font_name = 'DejaVuSans'
        else:
            self.font_name = 'Helvetica'  # fallback, но кириллица может не работать

        self.styles = getSampleStyleSheet()
        self.styles.add(ParagraphStyle(
            name='CyrillicNormal',
            fontName=self.font_name,
            fontSize=10,
            leading=12
        ))
        self.styles.add(ParagraphStyle(
            name='CyrillicTitle',
            fontName=self.font_name,
            fontSize=24,
            alignment=TA_CENTER,
            spaceAfter=20,
            textColor=colors.darkblue
        ))
        self.styles.add(ParagraphStyle(
            name='CyrillicHeading',
            fontName=self.font_name,
            fontSize=16,
            alignment=TA_LEFT,
            spaceAfter=10,
            textColor=colors.navy
        ))

    def fetch_vulnerabilities(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT id, severity, description, recommendation FROM vulnerabilities')
        rows = cursor.fetchall()
        conn.close()
        return rows

    def generate_chart(self, data, chart_type='pie'):
        severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for row in data:
            sev = row[1].lower()
            if sev in severity_count:
                severity_count[sev] += 1
        labels = [k.capitalize() for k, v in severity_count.items() if v > 0]
        values = [v for v in severity_count.values() if v > 0]
        if not values:
            return None

        fig, ax = plt.subplots(figsize=(4, 3))
        if chart_type == 'pie':
            ax.pie(values, labels=labels, autopct='%1.1f%%', startangle=90)
            ax.axis('equal')
            ax.set_title('Distribution by Severity')
        else:
            color_map = {'Critical':'red', 'High':'orange', 'Medium':'gold', 'Low':'lightgreen'}
            colors_list = [color_map.get(l, 'gray') for l in labels]
            ax.bar(labels, values, color=colors_list)
            ax.set_ylabel('Count')
            ax.set_title('Vulnerabilities by Severity')

        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=100, bbox_inches='tight')
        buf.seek(0)
        plt.close()
        return buf

    def generate_pdf(self, output_path):
        data = self.fetch_vulnerabilities()
        if not data:
            doc = SimpleDocTemplate(output_path, pagesize=A4)
            story = [Paragraph("No vulnerabilities found", self.styles['CyrillicTitle'])]
            doc.build(story)
            return

        doc = SimpleDocTemplate(output_path, pagesize=A4,
                                leftMargin=1*cm, rightMargin=1*cm,
                                topMargin=1*cm, bottomMargin=1*cm)
        story = []

        # Титульная страница
        if self.logo_path:
            try:
                img = Image(self.logo_path, width=2*inch, height=1*inch)
                story.append(img)
                story.append(Spacer(1, 0.2*inch))
            except:
                pass
        story.append(Paragraph("API Security Scan Report", self.styles['CyrillicTitle']))
        story.append(Spacer(1, 0.1*inch))
        story.append(Paragraph(f"Date: {datetime.datetime.now().strftime('%d.%m.%Y %H:%M')}",
                               self.styles['CyrillicNormal']))
        story.append(Spacer(1, 0.1*inch))
        story.append(Paragraph(f"Total vulnerabilities found: {len(data)}",
                               self.styles['CyrillicHeading']))
        story.append(PageBreak())

        # Графики
        story.append(Paragraph("Statistics", self.styles['CyrillicHeading']))
        story.append(Spacer(1, 0.1*inch))
        for chart_type in ['pie', 'bar']:
            buf = self.generate_chart(data, chart_type)
            if buf:
                img = Image(buf, width=4*inch, height=3*inch)
                story.append(img)
                story.append(Spacer(1, 0.2*inch))
        story.append(PageBreak())

        # Таблица
        story.append(Paragraph("List of Vulnerabilities", self.styles['CyrillicHeading']))
        story.append(Spacer(1, 0.1*inch))
        table_data = [['#', 'Severity', 'Description', 'Recommendation']]
        for idx, row in enumerate(data, 1):
            desc = Paragraph(row[2], self.styles['CyrillicNormal'])
            rec = Paragraph(row[3], self.styles['CyrillicNormal'])
            sev = Paragraph(row[1].capitalize(), self.styles['CyrillicNormal'])
            table_data.append([str(idx), sev, desc, rec])

        col_widths = [0.5*inch, 1*inch, 2.5*inch, 2.5*inch]
        table = Table(table_data, colWidths=col_widths, repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,0), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), self.font_name),
            ('FONTSIZE', (0,0), (-1,0), 10),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('FONTNAME', (0,1), (-1,-1), self.font_name),
            ('FONTSIZE', (0,1), (-1,-1), 9),
        ]))
        story.append(table)
        story.append(PageBreak())

        # Рекомендации
        story.append(Paragraph("Recommendations Summary", self.styles['CyrillicHeading']))
        story.append(Spacer(1, 0.1*inch))
        recs = set(row[3] for row in data if row[3])
        for r in recs:
            story.append(Paragraph(f"• {r}", self.styles['CyrillicNormal']))
            story.append(Spacer(1, 0.05*inch))

        doc.build(story)

    def generate_html(self, output_path):
        data = self.fetch_vulnerabilities()
        pie_buf = self.generate_chart(data, 'pie')
        bar_buf = self.generate_chart(data, 'bar')
        pie_base64 = bar_base64 = ''
        if pie_buf:
            pie_buf.seek(0)
            pie_base64 = base64.b64encode(pie_buf.read()).decode('utf-8')
        if bar_buf:
            bar_buf.seek(0)
            bar_base64 = base64.b64encode(bar_buf.read()).decode('utf-8')

        html = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"><title>API Security Report</title>
        <style>
            body {{ font-family: Arial; margin: 2em; background: #f8f9fa; }}
            .container {{ max-width: 1100px; margin: auto; background: white; padding: 2em; border-radius: 8px; }}
            h1 {{ color: #1a237e; text-align: center; }}
            .date {{ text-align: center; color: #555; }}
            .stats {{ display: flex; justify-content: center; gap: 2em; margin: 2em 0; }}
            .stat-box {{ background: #e3f2fd; padding: 1em; border-radius: 8px; text-align: center; }}
            .stat-number {{ font-size: 2em; font-weight: bold; color: #0d47a1; }}
            .charts {{ display: flex; flex-wrap: wrap; justify-content: center; gap: 1em; margin: 2em 0; }}
            .chart {{ flex: 1 1 300px; }}
            table {{ width: 100%; border-collapse: collapse; margin: 2em 0; }}
            th {{ background: #1a237e; color: white; padding: 8px; }}
            td {{ padding: 8px; border: 1px solid #ddd; vertical-align: top; }}
            .sev-critical {{ background: #ffebee; }}
            .sev-high {{ background: #fff3e0; }}
            .sev-medium {{ background: #fff8e1; }}
            .sev-low {{ background: #e8f5e9; }}
            .rec {{ background: #f1f8e9; padding: 1em; border-left: 4px solid #2e7d32; margin: 0.5em 0; }}
            .footer {{ text-align: center; margin-top: 2em; color: #888; }}
        </style>
        </head>
        <body>
        <div class="container">
            <h1>API Security Scan Report</h1>
            <div class="date">Date: {datetime.datetime.now().strftime('%d.%m.%Y %H:%M')}</div>
            <div class="stats">
                <div class="stat-box"><div class="stat-number">{len(data)}</div><div>Total Vulnerabilities</div></div>
            </div>
            <div class="charts">
                <div class="chart"><img src="data:image/png;base64,{pie_base64}" style="max-width:100%;"></div>
                <div class="chart"><img src="data:image/png;base64,{bar_base64}" style="max-width:100%;"></div>
            </div>
            <h2>Vulnerabilities List</h2>
            <table>
                <tr><th>#</th><th>Severity</th><th>Description</th><th>Recommendation</th></tr>
        """
        for idx, row in enumerate(data, 1):
            sev = row[1].lower()
            html += f"""
                <tr class="sev-{sev}">
                    <td>{idx}</td>
                    <td><strong>{row[1].capitalize()}</strong></td>
                    <td>{row[2]}</td>
                    <td>{row[3]}</td>
                </tr>
            """
        html += """
            </table>
            <h2>Recommendations Summary</h2>
        """
        recs = set(row[3] for row in data if row[3])
        for r in recs:
            html += f'<div class="rec">{r}</div>'
        html += """
            <div class="footer">Generated by API Security Scanner v1.0</div>
        </div>
        </body>
        </html>
        """
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
