import sqlite3
from datetime import datetime
import os

DB_PATH = "scanner.db"

def init_usage_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS usage (
            user_id TEXT PRIMARY KEY,
            scan_count INTEGER DEFAULT 0,
            month TEXT
        )
    ''')
    conn.commit()
    conn.close()

def get_current_month():
    return datetime.now().strftime("%Y-%m")

def can_scan(user_id="default"):
    init_usage_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    month = get_current_month()
    c.execute("SELECT scan_count FROM usage WHERE user_id = ? AND month = ?", (user_id, month))
    row = c.fetchone()
    conn.close()
    if row is None:
        return True  # ещё не сканировал в этом месяце
    return row[0] < 5

def increment_scan(user_id="default"):
    init_usage_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    month = get_current_month()
    c.execute('''
        INSERT INTO usage (user_id, month, scan_count)
        VALUES (?, ?, 1)
        ON CONFLICT(user_id) DO UPDATE SET
            scan_count = scan_count + 1,
            month = excluded.month
        WHERE user_id = ? AND month = ?
    ''', (user_id, month, user_id, month))
    conn.commit()
    conn.close()
