"""
Точка входа для создания .app
Запускает FastAPI сервер с автоматическим открытием браузера
"""
import sys
import os
import webbrowser
import time
import threading

# Важно: импортируем app напрямую, а не через строку "main:app"
from main import app
import uvicorn

def open_browser():
    """Открывает браузер через 2 секунды после запуска"""
    time.sleep(2)
    webbrowser.open("http://127.0.0.1:8000/docs")

if __name__ == "__main__":
    # Открываем браузер в отдельном потоке
    browser_thread = threading.Thread(target=open_browser)
    browser_thread.daemon = True
    browser_thread.start()
    
    # Запускаем сервер
    print("=" * 60)
    print("🔍 API Security Scanner v1.0")
    print("📚 ВКР МИФИ 2026 - Прутеану Мария")
    print("=" * 60)
    print("\n🌐 Swagger UI: http://127.0.0.1:8000/docs")
    print("\n🚀 Запуск сервера...\n")
    
    # Важно: передаём app напрямую, а не строку "main:app"
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="info"
    )
