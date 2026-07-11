FROM python:3.11-slim

WORKDIR /app

# Установка только CLI-зависимостей (без PyQt5)
COPY requirements-cli.txt .
RUN pip install --no-cache-dir -r requirements-cli.txt

# Копирование кода
COPY . .

# Установка шрифта для PDF (опционально)
RUN apt-get update && apt-get install -y fonts-dejavu && rm -rf /var/lib/apt/lists/*

# Точка входа – CLI
ENTRYPOINT ["python", "cli.py"]
