import sqlite3
import os

db_path = "vulnerabilities.db"  # путь к БД (если в корне)
if not os.path.exists(db_path):
    print(f"Файл {db_path} не найден.")
else:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    print("Таблицы в БД:", tables)
    conn.close()
