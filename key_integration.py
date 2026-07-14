from key_loader import DEFAULT_KEYS
import sys
import os

def apply_keys_from_files(app):
    print("[DEBUG] apply_keys_from_files вызвана!")
    print(f"[DEBUG] app.license_valid до: {getattr(app, 'license_valid', 'NOT SET')}")
    if not hasattr(app, 'license_valid'):
        app.license_valid = {'premium': False, 'enterprise': False}
        print("[DEBUG] license_valid создан в apply_keys_from_files")
    if DEFAULT_KEYS.get('premium'):
        app.settings['premium_key'] = DEFAULT_KEYS['premium']
        app.license_valid['premium'] = True
        print("[DEBUG] Premium ключ активирован")
    if DEFAULT_KEYS.get('enterprise'):
        app.settings['enterprise_key'] = DEFAULT_KEYS['enterprise']
        app.license_valid['enterprise'] = True
        print("[DEBUG] Enterprise ключ активирован")
    if DEFAULT_KEYS.get('api'):
        app.api_key = DEFAULT_KEYS['api']
        app.api_key_input.setText(app.api_key)
        app.settings['api_key'] = app.api_key
        print("[DEBUG] API-ключ установлен")
    print(f"[DEBUG] Итоговый license_valid: {app.license_valid}")
