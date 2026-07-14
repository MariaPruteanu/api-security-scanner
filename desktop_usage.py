import sqlite3
from usage_tracker import can_scan, increment_scan, DB_PATH, get_current_month
from PyQt5.QtWidgets import QMessageBox

def check_and_increment(parent, is_premium_or_enterprise):
    if is_premium_or_enterprise:
        return True
    if not can_scan():
        QMessageBox.warning(
            parent,
            "Лимит исчерпан",
            "Вы исчерпали лимит бесплатных сканирований (5 в месяц).\n\nПриобретите Pro-версию для неограниченного количества сканирований."
        )
        return False
    increment_scan()
    return True

def get_remaining_scans():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        month = get_current_month()
        c.execute("SELECT scan_count FROM usage WHERE user_id='default' AND month=?", (month,))
        row = c.fetchone()
        conn.close()
        if row is None:
            return 5
        return max(0, 5 - row[0])
    except:
        return 0

def get_tier_label(is_premium, is_enterprise):
    if is_enterprise:
        return "Enterprise"
    if is_premium:
        return "Pro (Premium)"
    return "Free"
