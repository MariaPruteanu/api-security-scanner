with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Заменяем placeholder'ы на нормальные тексты
replacements = {
    'target_label': '🎯 Цель:',
    'browse_btn': '📁 Обзор',
    'mode_local': 'Локально',
    'mode_cloud': 'Облако',
    'type_basic': 'Базовый',
    'type_premium': 'Premium',
    'type_enterprise': 'Enterprise',
    'api_key_placeholder': 'API ключ (для облака)',
    'start_scan_btn': '🚀 Начать сканирование',
    'stop_scan_btn': '⏹ Остановить',
}

for old, new in replacements.items():
    content = content.replace(f'"{old}"', f'"{new}"')
    content = content.replace(f"'{old}'", f"'{new}'")

# Улучшаем заголовок окна
content = content.replace('self.setWindowTitle("API Security Scanner Pro")', 
                          'self.setWindowTitle("🛡️ API Security Scanner Pro v2.0")')

with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("✅ desktop_app/main_window.py: Тексты интерфейса улучшены!")
