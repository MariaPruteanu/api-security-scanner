import sys
import traceback
from PyQt5.QtWidgets import QApplication
from desktop_app.main_window import MainWindow

try:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
except Exception as e:
    print("="*60)
    print("ОШИБКА ПРИ ЗАПУСКЕ:")
    traceback.print_exc()
    print("="*60)
    input("Нажмите Enter для выхода...")
