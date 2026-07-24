import sys

filename = "main_window.py"
with open(filename, 'r') as f:
    content = f.read()

debug_header = '''import sys
with open("/tmp/py_start.log", "w") as f:
    f.write("Python started\\n")
import traceback
sys.stderr = open("/tmp/debug.log", "w")
sys.excepthook = lambda exc_type, exc_value, exc_tb: sys.stderr.write(''.join(traceback.format_exception(exc_type, exc_value, exc_tb)))

'''

new_content = debug_header + content
with open(filename, 'w') as f:
    f.write(new_content)
print("✅ Отладочный код добавлен")
