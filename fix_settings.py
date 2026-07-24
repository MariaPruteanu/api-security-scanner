import sys
import os
import fileinput
import re

filename = "main_window.py"

# Ищем строки, где открывается settings.json, и заменяем на безопасный блок
with fileinput.FileInput(filename, inplace=True, backup='.bak') as file:
    for line in file:
        if 'settings.json' in line and 'os.path.join' not in line and 'with open' in line:
            # Заменяем на блок с try/except и созданием файла
            indent = ' ' * (len(line) - len(line.lstrip()))
            new_lines = [
                f'{indent}# Загружаем настройки (создаём файл, если его нет)\n',
                f'{indent}settings_path = os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))), "settings.json")\n',
                f'{indent}if not os.path.exists(settings_path):\n',
                f'{indent}    with open(settings_path, "w") as f:\n',
                f'{indent}        json.dump({{}}, f)\n',
                f'{indent}with open(settings_path, "r") as f:\n',
                f'{indent}    settings = json.load(f)\n',
            ]
            # Пропускаем старую строку, добавляем новые
            sys.stdout.write(''.join(new_lines))
        else:
            sys.stdout.write(line)
