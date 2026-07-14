import sys
import fileinput

filename = "main_window.py"
with fileinput.FileInput(filename, inplace=True, backup='.bak') as file:
    for line in file:
        sys.stdout.write(line)
        if line.strip().startswith('def run()'):
            sys.stdout.write('    print("run() started", file=open("/tmp/run.log", "w"))\n')
            sys.stdout.write('    import sys, os\n')
            sys.stdout.write('    print(f"QT_QPA_PLATFORM={os.environ.get(\"QT_QPA_PLATFORM\")}", file=open("/tmp/run.log", "a"))\n')
        if 'app = QApplication(sys.argv)' in line:
            sys.stdout.write('    print("QApplication created", file=open("/tmp/run.log", "a"))\n')
        if 'window.show()' in line:
            sys.stdout.write('    print("window.show() called", file=open("/tmp/run.log", "a"))\n')
            sys.stdout.write('    window.raise_()\n')
            sys.stdout.write('    window.activateWindow()\n')
            sys.stdout.write('    print("window.raise_() called", file=open("/tmp/run.log", "a"))\n')
        if 'sys.exit(app.exec_())' in line:
            sys.stdout.write('    print("app.exec_() started", file=open("/tmp/run.log", "a"))\n')
        if line.strip().startswith('def __init__(self)'):
            sys.stdout.write('        print("MainWindow.__init__ started", file=open("/tmp/init.log", "w"))\n')
        if 'self.init_ui()' in line:
            sys.stdout.write('        print("init_ui() called", file=open("/tmp/init.log", "a"))\n')
        if 'self.on_mode_changed(0)' in line:
            sys.stdout.write('        print("on_mode_changed called", file=open("/tmp/init.log", "a"))\n')
