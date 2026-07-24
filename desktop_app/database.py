import sqlite3
import json
import os
from datetime import datetime

def get_db_path():
    home = os.path.expanduser("~")
    app_support = os.path.join(home, "Library", "Application Support", "APIScannerPro")
    os.makedirs(app_support, exist_ok=True)   # создаём папку, если её нет
    return os.path.join(app_support, "scans.db")

DB_PATH = get_db_path()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            scan_type TEXT,
            timestamp TEXT,
            results TEXT,
            count INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def save_scan(target, scan_type, results):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.now().isoformat()
    results_json = json.dumps(results, ensure_ascii=False)
    c.execute('''
        INSERT INTO scans (target, scan_type, timestamp, results, count)
        VALUES (?, ?, ?, ?, ?)
    ''', (target, scan_type, timestamp, results_json, len(results)))
    conn.commit()
    conn.close()

def get_history(limit=50):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT id, target, scan_type, timestamp, count
        FROM scans ORDER BY timestamp DESC LIMIT ?
    ''', (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

def get_scan(id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT results FROM scans WHERE id = ?', (id,))
    row = c.fetchone()
    conn.close()
    if row:
        return json.loads(row[0])
    return None

def delete_scan(id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM scans WHERE id = ?', (id,))
    conn.commit()
    conn.close()

def clear_history():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM scans')
    conn.commit()
    conn.close()
