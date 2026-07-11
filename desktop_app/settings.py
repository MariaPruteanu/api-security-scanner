import os
import sys
import json

# Определяем путь к файлу настроек
if getattr(sys, 'frozen', False):
    # Если приложение собрано (внутри .app)
    # sys.executable — путь к APIScanner.app/Contents/MacOS/APIScanner
    # Поднимаемся на 3 уровня, чтобы попасть в папку dist
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(sys.executable)))
    SETTINGS_FILE = os.path.join(base_dir, "settings.json")
else:
    # Режим разработки (python run_desktop.py)
    SETTINGS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "settings.json")

DEFAULT_SETTINGS = {
    "last_target": "",
    "theme": "dark",
    "language": "ru",
    "license_key": "",
    "premium_key": "",
    "enterprise_key": "",
    "api_key": "",               # <- для облачного режима
    "api_url": "http://127.0.0.1:8000",
    "timeout": 30,
    "save_history": True,
    "max_history": 50
}

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return DEFAULT_SETTINGS.copy()

def save_settings(settings):
    # Убедимся, что папка существует
    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
        json.dump(settings, f, indent=2, ensure_ascii=False)
