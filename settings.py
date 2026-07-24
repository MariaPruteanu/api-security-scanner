import os
import json

def get_settings_path():
    home = os.path.expanduser("~")
    app_support = os.path.join(home, "Library", "Application Support", "APIScannerPro")
    os.makedirs(app_support, exist_ok=True)
    return os.path.join(app_support, "settings.json")

SETTINGS_FILE = get_settings_path()

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_settings(settings):
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(settings, f, indent=2)
