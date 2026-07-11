import json
import os

SETTINGS_FILE = os.path.join(os.path.dirname(__file__), "..", "settings.json")
DEFAULT_SETTINGS = {
    "theme": "dark",
    "language": "ru",
    "timeout": 30,
    "save_history": True,
    "max_history": 50,
    "premium_key": "",
    "enterprise_key": "",
    "api_url": "http://127.0.0.1:8000",
    "api_key": "",
    "last_target": ""
}

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Merge with defaults
                for key, value in DEFAULT_SETTINGS.items():
                    if key not in data:
                        data[key] = value
                return data
        except:
            return DEFAULT_SETTINGS.copy()
    return DEFAULT_SETTINGS.copy()

def save_settings(settings):
    with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
        json.dump(settings, f, ensure_ascii=False, indent=2)
