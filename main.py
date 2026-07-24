#!/usr/bin/env python3
<<<<<<< HEAD
import sys
from PyQt5.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget

app = QApplication(sys.argv)
window = QWidget()
window.setWindowTitle("Тест")
layout = QVBoxLayout()
label = QLabel("Привет! Если вы это видите, PyQt работает.")
layout.addWidget(label)
window.setLayout(layout)
window.resize(300, 100)
window.show()
sys.exit(app.exec_())
=======
# -*- coding: utf-8 -*-
"""
API Security Scanner Pro - Точка входа
"""
import sys
import os

# Добавляем путь к модулям
if getattr(sys, 'frozen', False):
    # Запущено из PyInstaller
    application_path = sys._MEIPASS
else:
    # Запущено из исходников
    application_path = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, application_path)

try:
    # Импортируем и запускаем главное окно
    from desktop_app.main_window import run
    run()
except Exception as e:
    print(f"❌ Критическая ошибка запуска: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc(file=sys.stderr)
    sys.exit(1)
>>>>>>> 05db96294ade776bf04401527428846dc52b3428
