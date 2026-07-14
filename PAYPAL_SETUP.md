# 🔧 Настройка PayPal для API Security Scanner Pro

## 1. Создание PayPal Developer аккаунта

1. Перейди на https://developer.paypal.com
2. Войди через свой PayPal аккаунт (или создай новый)
3. Перейди в **Dashboard → Apps & Credentials**

## 2. Создание приложения

### Sandbox (для тестов):
1. Убедись, что выбран режим **Sandbox**
2. Нажми **Create App**
3. Дай имя приложению (например, "API Scanner Pro")
4. Скопируй:
   - **Client ID** (начинается с `Aa...`)
   - **Client Secret** (нажми Show)

### Live (для продакшена):
1. Переключись на **Live** режим
2. Создай приложение аналогично
3. Скопируй Live credentials

## 3. Настройка переменных окружения

Открой `.env` и замени:

```bash
PAYPAL_CLIENT_ID=Aa тво_Client_ID_здесь
PAYPAL_CLIENT_SECRET=тво_Client_Secret_здесь
PAYPAL_MODE=sandbox  # Используй 'live' для продакшена
APP_URL=http://localhost:8000  # Или твой домен
