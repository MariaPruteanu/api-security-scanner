import os

def load_key(filename):
    """Загружает ключ из текстового файла в папке config/"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    filepath = os.path.join(base_dir, 'config', filename)
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read().strip()
    return None

def load_all_keys():
    """Загружает все ключи и возвращает словарь"""
    return {
        'premium': load_key('premium_key.txt'),
        'enterprise': load_key('enterprise_key.txt'),
        'api': load_key('api_key.txt'),
    }

# Если файлы есть – они будут автоматически применены при импорте
DEFAULT_KEYS = load_all_keys()
