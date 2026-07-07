# Используем официальный образ Python 3.11
FROM python:3.11-slim

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем зависимости
COPY requirements.txt .

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Копируем исходный код
COPY . .

# Создаём папку для отчётов
RUN mkdir -p output/reports

# Открываем порт для FastAPI
EXPOSE 8000

# Команда запуска
CMD ["python", "run.py"]

