with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
for i, line in enumerate(lines):
    # 1. Добавляем import os, если его нет (после import sys)
    if 'import sys' in line and 'import os' not in ''.join(lines[:i+5]):
        new_lines.append(line)
        new_lines.append('import os\n')
        continue
        
    new_lines.append(line)
    
    # 2. Автозагрузка лицензии сразу после загрузки настроек
    if 'self.settings = load_settings()' in line:
        indent = ' ' * 8 # Отступ внутри __init__
        new_lines.append(f"{indent}# Автозагрузка лицензионного ключа из файла\n")
        new_lines.append(f"{indent}license_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'license.key')\n")
        new_lines.append(f"{indent}if os.path.exists(license_file):\n")
        new_lines.append(f"{indent}    try:\n")
        new_lines.append(f"{indent}        with open(license_file, 'r', encoding='utf-8') as f:\n")
        new_lines.append(f"{indent}            saved_key = f.read().strip()\n")
        new_lines.append(f"{indent}            if saved_key:\n")
        new_lines.append(f"{indent}                self.settings['license_key'] = saved_key\n")
        new_lines.append(f"{indent}                save_settings(self.settings)\n")
        new_lines.append(f"{indent}    except Exception:\n")
        new_lines.append(f"{indent}        pass\n")
        
    # 3. Улучшение текстов интерфейса (точная замена строк)
    if 'self.setWindowTitle("API Security Scanner Pro")' in line:
        new_lines[-1] = line.replace('"API Security Scanner Pro"', '"🛡️ API Security Scanner Pro v2.0"')
        
    if 'self.target_input.setPlaceholderText("Enter URL or path to OpenAPI spec...")' in line:
        new_lines[-1] = line.replace('"Enter URL or path to OpenAPI spec..."', '"Введите URL API или путь к OpenAPI спецификации..."')
        
    if 'self.api_key_input.setPlaceholderText("API Key")' in line:
        new_lines[-1] = line.replace('"API Key"', '"API ключ (для облака)"')

with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print("✅ Интерфейс улучшен, лицензия подключена безопасно!")
