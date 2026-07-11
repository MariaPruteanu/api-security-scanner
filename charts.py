import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io
import base64
from collections import Counter
import sqlite3

def get_severity_data(scan_id):
    conn = sqlite3.connect("scanner.db")
    c = conn.cursor()
    tables = c.execute("SELECT name FROM sqlite_master WHERE type='table' AND (name='vulnerabilities' OR name='vulns' OR name='issues')").fetchall()
    if not tables:
        conn.close()
        return Counter()
    table_name = tables[0][0]
    c.execute(f"PRAGMA table_info({table_name})")
    columns = [col[1] for col in c.fetchall()]
    if 'severity' not in columns:
        conn.close()
        return Counter()
    if 'scan_id' in columns:
        c.execute(f"SELECT severity FROM {table_name} WHERE scan_id=?", (scan_id,))
    else:
        c.execute(f"SELECT severity FROM {table_name}")
    rows = c.fetchall()
    conn.close()
    severity_counts = Counter([r[0] for r in rows])
    return severity_counts

def generate_severity_pie_chart(severity_data, output_format='base64'):
    if not severity_data:
        return None
    labels = list(severity_data.keys())
    sizes = list(severity_data.values())
    colors = ['#ff4d4d', '#ffa64d', '#ffd24d', '#66b3ff']
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors, startangle=90)
    ax.axis('equal')
    plt.title('Распределение уязвимостей по критичности')
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=100, bbox_inches='tight')
    plt.close(fig)
    buf.seek(0)
    if output_format == 'base64':
        return base64.b64encode(buf.read()).decode('utf-8')
    else:
        return buf.getvalue()

def generate_severity_bar_chart(severity_data, output_format='base64'):
    if not severity_data:
        return None
    labels = list(severity_data.keys())
    sizes = list(severity_data.values())
    colors = ['#ff4d4d', '#ffa64d', '#ffd24d', '#66b3ff']
    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.bar(labels, sizes, color=colors)
    ax.set_ylabel('Количество')
    ax.set_title('Уязвимости по критичности')
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{int(height)}', xy=(bar.get_x() + bar.get_width()/2, height),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom')
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=100, bbox_inches='tight')
    plt.close(fig)
    buf.seek(0)
    if output_format == 'base64':
        return base64.b64encode(buf.read()).decode('utf-8')
    else:
        return buf.getvalue()
