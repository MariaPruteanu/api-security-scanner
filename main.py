#!/usr/bin/env python3
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
