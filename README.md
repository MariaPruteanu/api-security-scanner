# 🛡️ API Security Scanner Pro

**API Security Scanner Pro** — это профессиональный десктопный инструмент для сканирования уязвимостей в API-спецификациях (OpenAPI, Swagger, Postman). Поддерживает локальный и облачный режимы, генерацию отчётов, лицензирование и интеграцию с платежными системами.

---

## 🇬🇧 English

### Features

- ✅ Scan OpenAPI 3.x, Swagger 2.0, Postman Collections
- ✅ 100+ security rules based on OWASP API Security Top 10
- ✅ Local and cloud scanning modes
- ✅ Generate PDF/HTML/JSON reports with charts
- ✅ License management (Free, Premium, Enterprise)
- ✅ Payment via **DeFi (USDT/Solana)** for international customers
- ✅ Payment via **Boosty** for Russian customers
- ✅ Auto-update check
- ✅ CI/CD ready (CLI, Docker, GitHub Actions)

### Installation

#### macOS
1. Download the latest `.app` from [Releases](https://github.com/MariaPruteanu/api-security-scanner/releases)
2. Open `APIScannerProLauncher.command` to start the app
3. If macOS blocks the app, right-click → Open

#### From source
```bash
git clone https://github.com/MariaPruteanu/api-security-scanner.git
cd api-security-scanner
pip install -r requirements.txt
python main_window.py
Pricing
Plan	Monthly	Yearly (25% off)
Free	5 scans/month	—
Premium	9 USDT / 810 RUB	74.25 USDT / 6682.5 RUB
Enterprise	Contact us	Contact us
Payment Methods
Region	Method
🇷🇺 Russia	Boosty
🌍 International	DeFi (USDT/Solana)
How to Use
Enter a target — paste an OpenAPI URL or select a local YAML/JSON file.

Choose scan type — Basic (Free), Premium, or Enterprise.

Click "Start Scan" — wait for results.

View results — vulnerabilities are displayed in a table with severity badges.

Export report — save as PDF, HTML, or JSON.

Buy Pro — purchase a license via DeFi or Boosty.

Enter license key — paste your key to unlock Premium/Enterprise features.

Cloud Mode
To use cloud scanning, you need a backend running:

bash
cd api-security-scanner
uvicorn main:app --host 0.0.0.0 --port 8000
Or use the hosted backend: https://api-security-scanner.onrender.com

CLI & Docker
bash
# CLI
python cli.py https://petstore.swagger.io/v2/swagger.json --type premium --output pdf

# Docker
docker build -t api-scanner .
docker run --rm api-scanner ./openapi.yaml --output json
License Activation
After payment, you'll receive a license key.

Go to Settings → paste your key → click "Save".

Or use the "Enter Key" button in the main window.

Development
bash
# Install dependencies
pip install -r requirements.txt

# Build the app
python build.py

# Run tests
pytest
Contributing
Pull requests are welcome! For major changes, please open an issue first.

License
MIT © Maria Pruteanu
🇷🇺 Русский
Возможности
✅ Сканирование OpenAPI 3.x, Swagger 2.0, Postman Collections

✅ 100+ правил безопасности на основе OWASP API Security Top 10

✅ Локальный и облачный режимы сканирования

✅ Генерация отчётов в PDF/HTML/JSON с графиками

✅ Управление лицензиями (Free, Premium, Enterprise)

✅ Оплата через DeFi (USDT/Solana) для иностранных клиентов

✅ Оплата через Boosty для российских клиентов

✅ Проверка обновлений

✅ Готовность для CI/CD (CLI, Docker, GitHub Actions)

Установка
macOS
Скачайте последнюю версию .app из Releases

Откройте APIScannerProLauncher.command для запуска приложения

Если macOS блокирует приложение — нажмите правой кнопкой → Открыть

Из исходников
bash
git clone https://github.com/MariaPruteanu/api-security-scanner.git
cd api-security-scanner
pip install -r requirements.txt
python main_window.py
Цены
Тариф	Месяц	Год (скидка 25%)
Free	5 сканирований/мес	—
Premium	9 USDT / 810 ₽	74.25 USDT / 6682.5 ₽
Enterprise	Свяжитесь с нами	Свяжитесь с нами
Способы оплаты
Регион	Способ оплаты
🇷🇺 Россия	Boosty
🌍 Зарубежье	DeFi (USDT/Solana)
Как использовать
Укажите цель — вставьте URL OpenAPI или выберите локальный YAML/JSON-файл.

Выберите тип сканирования — Basic (Бесплатный), Premium или Enterprise.

Нажмите «Начать сканирование» — дождитесь результатов.

Просмотрите результаты — уязвимости отображаются в таблице с цветовыми метками.

Экспортируйте отчёт — сохраните в PDF, HTML или JSON.

Купите Pro — приобретите лицензию через DeFi или Boosty.

Введите лицензионный ключ — вставьте ключ для активации Premium/Enterprise.

Облачный режим
Для использования облачного сканирования нужен запущенный бэкенд:

bash
cd api-security-scanner
uvicorn main:app --host 0.0.0.0 --port 8000
Или используйте хостинг-версию: https://api-security-scanner.onrender.com

CLI и Docker
bash
# CLI
python cli.py https://petstore.swagger.io/v2/swagger.json --type premium --output pdf

# Docker
docker build -t api-scanner .
docker run --rm api-scanner ./openapi.yaml --output json
Активация лицензии
После оплаты вы получите лицензионный ключ.

Перейдите в Настройки → вставьте ключ → нажмите «Сохранить».

Или используйте кнопку «Enter Key» в главном окне.

Разработка
bash
# Установка зависимостей
pip install -r requirements.txt

# Сборка приложения
python build.py

# Запуск тестов
pytest
Вклад в проект
Pull Request'ы приветствуются! Для крупных изменений откройте issue.

Лицензия
MIT © Maria Pruteanu

📦 Releases
Download the latest version: GitHub Releases
📬 Contact
Telegram: @MariaPruteanu

Email: mashatira@gmail.com

Boosty: https://boosty.to/mariapruteanu

Made with ❤️ by Maria Pruteanu
