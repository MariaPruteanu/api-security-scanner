import stripe
import os
from dotenv import load_dotenv

load_dotenv()
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# Попробуем получить список продуктов (это простой GET-запрос)
try:
    products = stripe.Product.list(limit=1)
    print("✅ Подключение к Stripe успешно! Количество продуктов:", len(products.data))
except Exception as e:
    print("❌ Ошибка:", e)
