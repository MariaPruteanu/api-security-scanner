import sys

filename = "main_window.py"
with open(filename, 'r') as f:
    content = f.read()

# Проверяем, есть ли уже эти строки
if 'QT_QPA_PLATFORM' in content:
    print("QT_QPA_PLATFORM уже установлен, пропускаем")
    sys.exit(0)

# Вставляем строки в начало
header = 'import os\nos.environ["QT_QPA_PLATFORM"] = "cocoa"\n\n'
with open(filename, 'w') as f:
    f.write(header + content)

print("✅ QT_QPA_PLATFORM добавлен в начало main_window.py")
