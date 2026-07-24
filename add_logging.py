import sys

filename = "main_window.py"
with open(filename, 'r') as f:
    content = f.read()

# Проверяем, есть ли уже логирование
if 'sys.stderr = open' in content:
    print("Логирование уже добавлено, пропускаем")
    sys.exit(0)

header = '''import sys
sys.stderr = open("/tmp/apis.err", "w")
sys.stdout = open("/tmp/apis.out", "w")
'''
with open(filename, 'w') as f:
    f.write(header + content)
print("✅ Логирование добавлено в main_window.py")
