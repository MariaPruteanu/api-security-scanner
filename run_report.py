import sqlite3
import sys
from report_generator import ReportGenerator

def get_last_scan_id():
    conn = sqlite3.connect("scanner.db")
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND (name='scan_tasks' OR name='scans' OR name='scan_results')")
    table = c.fetchone()
    if not table:
        print("❌ Таблица сканирований не найдена.")
        conn.close()
        return None
    table_name = table[0]
    c.execute(f"SELECT id FROM {table_name} ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

if __name__ == "__main__":
    if len(sys.argv) > 1:
        scan_id = int(sys.argv[1])
    else:
        scan_id = get_last_scan_id()
        if scan_id is None:
            print("❌ Нет завершённых сканирований.")
            sys.exit(1)
    print(f"🔹 Генерация отчёта для сканирования #{scan_id}...")
    generator = ReportGenerator(scan_id, f"report_{scan_id}.pdf")
    generator.generate()
    print(f"✅ Отчёт сохранён: report_{scan_id}.pdf")
