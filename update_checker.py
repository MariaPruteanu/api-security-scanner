import requests
from version import VERSION
import threading
from PyQt5.QtWidgets import QMessageBox
import webbrowser

def check_for_updates():
    try:
        url = "https://api.github.com/repos/MariaPruteanu/api-security-scanner/releases/latest"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            latest = resp.json()
            latest_version = latest.get('tag_name', '').lstrip('v')
            if latest_version and latest_version != VERSION:
                return latest_version, latest.get('html_url')
    except:
        pass
    return None, None

def check_updates_async(parent):
    def run():
        latest_version, url = check_for_updates()
        if latest_version:
            reply = QMessageBox.question(
                parent, "Обновление доступно",
                f"Доступна новая версия {latest_version}.\n\nХотите перейти на страницу загрузки?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                webbrowser.open(url)
    threading.Thread(target=run, daemon=True).start()
