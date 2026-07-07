# 🔍 API Security Scanner

<div align="center">

[![CI/CD Pipeline](https://github.com/MariaPruteanu/api-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/MariaPruteanu/api-security-scanner/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/MariaPruteanu/api-security-scanner/branch/main/graph/badge.svg)](https://codecov.io/gh/MariaPruteanu/api-security-scanner)

**Инструмент автоматизированного анализа защищённости API на основе OWASP API Security Top 10 (2023)**

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688.svg)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED.svg)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OWASP](https://img.shields.io/badge/OWASP-API%20Top%2010-red.svg)](https://owasp.org/www-project-api-security/)

[Быстрый старт](#-быстрый-старт) • [Возможности](#-возможности) • [Docker](#-запуск-в-docker) • [Документация](#-документация)

</div>

---

## 📋 О проекте

**API Security Scanner** — это инструмент для автоматического поиска уязвимостей в REST API. Сканер сочетает **статический анализ OpenAPI/Swagger** спецификаций с **динамическим тестированием** (DAST) на основе 45+ YAML-правил.

### 🎯 Ключевые особенности

- ✅ **45+ YAML-правил** — гибкая система проверок без изменения кода
- ✅ **Покрытие OWASP API Top 10 (2023)** — все 10 категорий
- ✅ **Асинхронное сканирование** — httpx + asyncio
- ✅ **JWT/Bearer Token** — поддержка аутентификации
- ✅ **Swagger UI** — удобный веб-интерфейс
- ✅ **HTML/JSON/CSV отчёты** — через Jinja2
- ✅ **Docker-контейнеризация** — запуск в один клик

---

## 🚀 Быстрый старт

### Локальный запуск

```bash
# 1. Клонируем репозиторий
git clone https://github.com/MariaPruteanu/api-security-scanner.git
cd api-security-scanner

# 2. Создаём виртуальное окружение
python3 -m venv venv
source venv/bin/activate  # macOS/Linux

# 3. Устанавливаем зависимости
pip install -r requirements.txt

# 4. Запускаем сканер
python3 run.py
# Trigger CI
