# 🔧 Настройка Stripe для API Security Scanner Pro

## 1. Регистрация в Stripe

1. Перейди на https://stripe.com и создай аккаунт
2. Перейди в Dashboard → Developers → API keys
3. Скопируй ключи:
   - **Publishable key** (начинается с `pk_test_...`)
   - **Secret key** (начинается с `sk_test_...`)

## 2. Настройка переменных окружения

Открой файл `.env` и замени значения:

```bash
STRIPE_SECRET_KEY=sk_test_тво_секретный_ключ
STRIPE_PUBLIC_KEY=pk_test_твой_публичный_ключ
WEBHOOK_SECRET=whsec_твой_вебхук_секрет
APP_URL=http://localhost:8000
