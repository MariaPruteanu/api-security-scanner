#!/usr/bin/env python3
"""
API Security Scanner - CLI
Usage:
    python cli.py <target> [--type basic|premium|enterprise] [--output json|html|pdf] [--out-file FILE]
Example:
    python cli.py https://petstore.swagger.io/v2/swagger.json --type premium --output json
    python cli.py ./openapi.yaml --output pdf --out-file report.pdf
"""
import sys
import os
import json
import asyncio
import argparse
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.core import APIScanner
from loader import load_specification

async def scan(target, scan_type='basic'):
    scanner = APIScanner(base_url=target, scan_type=scan_type)
    results = await scanner.run_scan()
    return results

def generate_html_from_results(results, target):
    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>API Security Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 2em; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background-color: #f2f2f2; }}
</style>
</head>
<body>
<h1>API Security Scan Report</h1>
<p><strong>Target:</strong> {target}</p>
<p><strong>Date:</strong> {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p><strong>Total vulnerabilities:</strong> {len(results)}</p>
<table>
<tr><th>#</th><th>Severity</th><th>Description</th><th>Endpoint</th></tr>
"""
    for i, item in enumerate(results, 1):
        severity = item.get('severity', 'UNKNOWN')
        desc = item.get('description', '')
        endpoint = item.get('endpoint', 'N/A')
        html += f"<tr><td>{i}</td><td>{severity}</td><td>{desc}</td><td>{endpoint}</td></tr>"
    html += """
</table>
</body>
</html>"""
    return html

def generate_pdf_from_results(results, target, out_file):
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    import os

    # Ищем доступные шрифты для кириллицы
    font_paths = [
        "DejaVuSans.ttf",
        "/System/Library/Fonts/Supplemental/Arial.ttf",  # macOS
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",  # Linux
        "C:/Windows/Fonts/arial.ttf",  # Windows
    ]
    font_name = 'Helvetica'  # fallback
    for path in font_paths:
        if os.path.exists(path):
            try:
                pdfmetrics.registerFont(TTFont('CustomFont', path))
                font_name = 'CustomFont'
                break
            except:
                continue

    doc = SimpleDocTemplate(out_file, pagesize=A4)
    styles = getSampleStyleSheet()
    # Используем уникальные имена, чтобы не конфликтовать со встроенными стилями
    styles.add(ParagraphStyle(name='CustomTitle', fontName=font_name, fontSize=20, alignment=1, spaceAfter=20))
    styles.add(ParagraphStyle(name='CustomBody', fontName=font_name, fontSize=10, leading=12))

    story = []
    story.append(Paragraph("API Security Scan Report", styles['CustomTitle']))
    story.append(Spacer(1, 0.2*inch))
    story.append(Paragraph(f"Target: {target}", styles['CustomBody']))
    story.append(Paragraph(f"Date: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['CustomBody']))
    story.append(Paragraph(f"Total vulnerabilities: {len(results)}", styles['CustomBody']))
    story.append(Spacer(1, 0.2*inch))

    table_data = [['#', 'Severity', 'Description', 'Endpoint']]
    for i, item in enumerate(results, 1):
        table_data.append([
            str(i),
            item.get('severity', 'UNKNOWN'),
            item.get('description', ''),
            item.get('endpoint', 'N/A')
        ])
    table = Table(table_data, colWidths=[0.5*inch, 1*inch, 2.5*inch, 1.5*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,0), 'CENTER'),
        ('FONTNAME', (0,0), (-1,-1), font_name),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(table)
    doc.build(story)
    return out_file

def main():
    parser = argparse.ArgumentParser(description="API Security Scanner")
    parser.add_argument("target", help="URL or path to OpenAPI/Swagger specification")
    parser.add_argument("--type", choices=['basic', 'premium', 'enterprise'], default='basic',
                        help="Scan type (default: basic)")
    parser.add_argument("--output", choices=['json', 'html', 'pdf'], default='json',
                        help="Output format (default: json)")
    parser.add_argument("--out-file", help="Output file path (default: stdout or auto-generated)")

    args = parser.parse_args()

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    results = loop.run_until_complete(scan(args.target, args.type))

    if args.output == 'json':
        output = json.dumps(results, ensure_ascii=False, indent=2)
        if args.out_file:
            with open(args.out_file, 'w', encoding='utf-8') as f:
                f.write(output)
        else:
            print(output)

    elif args.output == 'html':
        html_content = generate_html_from_results(results, target=args.target)
        if args.out_file:
            with open(args.out_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
        else:
            print(html_content)

    elif args.output == 'pdf':
        if not args.out_file:
            args.out_file = "report.pdf"
        generate_pdf_from_results(results, target=args.target, out_file=args.out_file)
        print(f"PDF saved to {args.out_file}")

if __name__ == '__main__':
    main()
