# Упрощённый репортёр без HTML-стилей для PDF
class Reporter:
    def generate_html(self, results):
        # Если нужен HTML, возвращаем простой HTML без стилей
        html = "<h1>API Security Report</h1><ul>"
        for r in results:
            html += f"<li>{r.get('description', '')}</li>"
        html += "</ul>"
        return html
