import sys
import os
import fileinput

filename = "main_window.py"

# Строка, которую будем искать для вставки
insert_block = '''
# Функция получения пути к ресурсам (работает и для .app, и для исходников)
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    if getattr(sys, 'frozen', False):
        # Запуск в собранном приложении
        base_path = sys._MEIPASS
    else:
        # Запуск из исходников
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)
'''

# Вставляем после импортов (после строки с 'import os')
with fileinput.FileInput(filename, inplace=True, backup='.bak') as file:
    for line in file:
        sys.stdout.write(line)
        if line.strip().startswith('import os') and 'resource_path' not in ''.join(file):
            sys.stdout.write(insert_block)
