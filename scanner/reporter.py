from jinja2 import Environment, FileSystemLoader
from datetime import datetime
import os

class HTMLReporter:
    def __init__(self, findings: list, target_url: str, scanned_by: str):
        self.findings = findings
        self.target_url = target_url
        self.scanned_by = scanned_by
        self.scan_date = datetime.now().strftime("%Y-%m-%d %H:%M")
        self.critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        self.high = sum(1 for f in findings if f.get("severity") == "HIGH")
        self.medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    
    def save(self, filename: str):
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        html = self._generate_html()
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"📄 Отчёт сохранён: {filename}")
    
    def _generate_html(self) -> str:
        return f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Отчёт сканирования API - {self.scan_date}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }}
        .stat {{ padding: 20px; border-radius: 8px; text-align: center; color: white; }}
        .critical {{ background: #e74c3c; }}
        .high {{ background: #e67e22; }}
        .medium {{ background: #f1c40f; color: #333; }}
        .vulnerability {{ border: 1px solid #ddd; margin: 15px 0; padding: 20px; border-radius: 8px; border-left: 5px solid; }}
        .vulnerability.CRITICAL {{ border-left-color: #e74c3c; }}
        .vulnerability.HIGH {{ border-left-color: #e67e22; }}
        .vulnerability.MEDIUM {{ border-left-color: #f1c40f; }}
        .severity {{ display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; }}
        .severity.CRITICAL {{ background: #e74c3c; }}
        .severity.HIGH {{ background: #e67e22; }}
        .severity.MEDIUM {{ background: #f1c40f; color: #333; }}
        .evidence {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }}
        .recommendation {{ background: #d5f5e3; padding: 15px; border-radius: 5px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Отчёт сканирования безопасности API</h1>
        <p><strong>Цель:</strong> {self.target_url}</p>
        <p><strong>Дата:</strong> {self.scan_date}</p>
        <p><strong>Сканировал:</strong> {self.scanned_by}</p>
        <p><strong>Всего уязвимостей:</strong> {len(self.findings)}</p>
        
        <h2>📊 Сводка по критичности</h2>
        <div class="summary">
            <div class="stat critical"><h3>{self.critical}</h3><p>Critical</p></div>
            <div class="stat high"><h3>{self.high}</h3><p>High</p></div>
            <div class="stat medium"><h3>{self.medium}</h3><p>Medium</p></div>
        </div>
        
        <h2>🚨 Обнаруженные уязвимости</h2>
"""
        for i, f in enumerate(self.findings, 1):
            html += f"""
        <div class="vulnerability {f.get('severity', 'MEDIUM')}">
            <h3>#{i} - {f.get('vulnerability')}</h3>
            <span class="severity {f.get('severity')}">{f.get('severity')}</span>
            <p><strong>OWASP:</strong> {f.get('owasp')}</p>
            <p><strong>Endpoint:</strong> <code>{f.get('endpoint')}</code></p>
            <div class="evidence"><strong>Доказательство:</strong><br>{f.get('evidence')}</div>
            <div class="recommendation"><strong>💡 Рекомендация:</strong><br>{f.get('recommendation')}</div>
        </div>
"""
        html += f"""
        <p style="margin-top: 40px; color: #7f8c8d; text-align: center;">
            API Security Scanner v1.0 | ВКР МИФИ 2026 | Прутеану Мария М24-505
        </p>
    </div>
</body>
</html>"""
        return html
