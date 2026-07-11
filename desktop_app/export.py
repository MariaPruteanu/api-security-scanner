import json
import os
from datetime import datetime

def export_json(results, filepath):
    """Сохраняет результаты в JSON."""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=4)
    return filepath

def export_html(results, filepath):
    """Сохраняет результаты в HTML-таблицу."""
    html = """
    <html>
    <head><meta charset="UTF-8"><title>Отчёт сканирования</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        .high { background-color: #ffcccc; }
        .medium { background-color: #ffffcc; }
        .low { background-color: #ccffcc; }
        .critical { background-color: #ff9999; }
    </style>
    </head>
    <body>
    <h1>Отчёт сканирования API</h1>
    <p>Дата: {date}</p>
    <table>
    <tr><th>ID</th><th>Уровень</th><th>Описание</th></tr>
    """
    for item in results:
        severity = item.get('severity', '').lower()
        cls = severity if severity in ('high', 'medium', 'low', 'critical') else ''
        html += f"<tr class='{cls}'><td>{item.get('id', '')}</td><td>{item.get('severity', '')}</td><td>{item.get('description', '')}</td></tr>"
    html += "</table></body></html>"
    html = html.format(date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html)
    return filepath

def export_pdf(results, filepath):
    """Создаёт PDF-отчёт (требуется библиотека reportlab)."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []
        elements.append(Paragraph("Отчёт сканирования API", styles['Title']))
        elements.append(Spacer(1, 0.25*inch))
        elements.append(Paragraph(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 0.25*inch))
        data = [["ID", "Уровень", "Описание"]]
        for item in results:
            data.append([
                item.get('id', ''),
                item.get('severity', ''),
                item.get('description', '')
            ])
        table = Table(data, colWidths=[1*inch, 1*inch, 4*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('BACKGROUND', (0,1), (-1,-1), colors.beige),
            ('GRID', (0,0), (-1,-1), 1, colors.black)
        ]))
        elements.append(table)
        doc.build(elements)
        return filepath
    except ImportError:
        raise Exception("Библиотека reportlab не установлена. Установите: pip install reportlab")
