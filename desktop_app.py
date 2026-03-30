"""
Desktop GUI приложение для API Security Scanner
Запускает сервер и открывает нативное окно
"""
import webview
import uvicorn
import threading
import time
import sys

def start_server():
    """Запускает FastAPI сервер в отдельном потоке"""
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="warning"
    )

if __name__ == "__main__":
    print("=" * 60)
    print("🔍 API Security Scanner v1.0")
    print("📚 ВКР МИФИ 2026 - Прутеану Мария")
    print("=" * 60)
    print("\n🚀 Запуск сервера...\n")
    
    # Запуск сервера в фоне
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    
    # Ждём запуска сервера
    time.sleep(3)
    
    # Создаём окно приложения
    window = webview.create_window(
        'API Security Scanner v1.0',
        'http://127.0.0.1:8000/docs',
        width=1400,
        height=900,
        resizable=True,
        fullscreen=False,
        min_size=(1024, 768)
    )
    
    # Запускаем GUI
    print("🌐 Открытие интерфейса...\n")
    webview.start()
