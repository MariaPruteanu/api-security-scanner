import sys
import fileinput

filename = "main_window.py"

with fileinput.FileInput(filename, inplace=True, backup='.bak') as file:
    for line in file:
        sys.stdout.write(line)
        if line.strip().startswith('def __init__(self)'):
            sys.stdout.write('        print("MainWindow.__init__ started", file=open("/tmp/init.log", "w"))\n')
        if 'self.init_ui()' in line:
            sys.stdout.write('        print("init_ui() called", file=open("/tmp/init.log", "a"))\n')
        if 'self.on_mode_changed(0)' in line:
            sys.stdout.write('        print("on_mode_changed called", file=open("/tmp/init.log", "a"))\n')
