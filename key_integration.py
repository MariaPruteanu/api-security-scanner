import os
from key_loader import DEFAULT_KEYS

def apply_keys_from_files(app):
    """
    Применяет ключи из файлов к объекту главного окна (MainWindow).
    """
    if DEFAULT_KEYS.get('premium'):
        app.settings['premium_key'] = DEFAULT_KEYS['premium']
        app.license_valid['premium'] = True
    if DEFAULT_KEYS.get('enterprise'):
        app.settings['enterprise_key'] = DEFAULT_KEYS['enterprise']
        app.license_valid['enterprise'] = True
    if DEFAULT_KEYS.get('api'):
        app.api_key = DEFAULT_KEYS['api']
        app.api_key_input.setText(app.api_key)
        app.settings['api_key'] = app.api_key
