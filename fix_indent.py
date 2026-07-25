import sys
import re

filename = "main_window.py"
with open(filename, 'r') as f:
    lines = f.readlines()

# Исправляем отступы для методов класса (должны быть 4 пробела)
fixed_lines = []
for i, line in enumerate(lines):
    # Если строка содержит def buy_pro или def _defi_payment_dialog
    if 'def buy_pro' in line or 'def _defi_payment_dialog' in line:
        # Убираем все пробелы в начале и ставим ровно 4
        line = '    ' + line.lstrip()
    # Если строка содержит QMessageBox и находится внутри метода
    elif 'QMessageBox' in line or 'import requests' in line or 'clipboard' in line or 'webbrowser' in line:
        # Проверяем, что это внутри метода (не на уровне класса)
        # Находим предыдущие строки, чтобы определить контекст
        prev_lines = fixed_lines[-5:] if len(fixed_lines) >= 5 else fixed_lines
        is_inside_method = any('def buy_pro' in l or 'def _defi_payment_dialog' in l for l in prev_lines)
        if is_inside_method:
            # Убираем лишние пробелы и ставим 8 пробелов (для строк внутри метода)
            if not line.lstrip().startswith('#'):
                line = '        ' + line.lstrip()
    fixed_lines.append(line)

with open(filename, 'w') as f:
    f.writelines(fixed_lines)

print("✅ Отступы исправлены")
