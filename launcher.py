#!/usr/bin/env python
import os
import sys
import time
import socket

# Устанавливаем рабочую директорию в корень проекта
os.chdir(os.path.dirname(os.path.abspath(__file__)))

def start_backend():
    """Проверяет, запущен ли бэкенд, и если нет – запускает его в фоне как демон"""
    # Проверяем, запущен ли сервер на порту 8000
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', 8000))
    sock.close()
    if result == 0:
        print("✅ Сервер уже запущен")
        return

    print("🚀 Запуск бэкенда...")
    # Запускаем main.py через nohup, чтобы процесс не зависел от терминала
    os.system(f"nohup {sys.executable} main.py > backend.log 2>&1 &")
    # Даём серверу время запуститься
    time.sleep(2)
    print("✅ Бэкенд запущен (смотрите backend.log для логов)")

start_backend()

# Запускаем GUI
from main_window import run
run()
