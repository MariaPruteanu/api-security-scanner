with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
for i, line in enumerate(lines):
    new_lines.append(line)
    
    # Добавляем import os после import sys
    if line.strip() == 'import sys' and i < 50:
        if not any('import os' in l for l in lines[:i+5]):
            new_lines.append('import os\n')
    
    # Добавляем загрузку лицензии после load_settings()
    if 'self.settings = load_settings()' in line:
        indent = '        '
        new_lines.append(f"{indent}# Автозагрузка лицензионного ключа\n")
        new_lines.append(f"{indent}license_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'license.key')\n")
        new_lines.append(f"{indent}if os.path.exists(license_file):\n")
        new_lines.append(f"{indent}    try:\n")
        new_lines.append(f"{indent}        with open(license_file, 'r', encoding='utf-8') as f:\n")
        new_lines.append(f"{indent}            self.settings['license_key'] = f.read().strip()\n")
        new_lines.append(f"{indent}    except Exception:\n")
        new_lines.append(f"{indent}        pass\n")

with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print("✅ Лицензия добавлена безопасно!")
