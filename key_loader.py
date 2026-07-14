import os
import sys

def load_key(filename):
    # Ищем config в папке, где находится сам key_loader.py (это Resources)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    filepath = os.path.join(base_dir, 'config', filename)
    print(f"[DEBUG] Ищем ключ: {filepath}")
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            print(f"[DEBUG] Найден ключ для {filename}: {content[:10]}...")
            return content
    else:
        print(f"[DEBUG] Файл не найден: {filepath}")
    return None

def load_all_keys():
    keys = {
        'premium': load_key('premium_key.txt'),
        'enterprise': load_key('enterprise_key.txt'),
        'api': load_key('api_key.txt'),
    }
    print(f"[DEBUG] Загруженные ключи: {list(keys.keys())}")
    return keys

DEFAULT_KEYS = load_all_keys()
