import os
from dotenv import load_dotenv

load_dotenv()

# Stripe
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
YOUR_DOMAIN = os.getenv("YOUR_DOMAIN", "http://localhost:4242")

# SMTP
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.yandex.ru")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

# Режим симуляции (если нет ключей Stripe)
USE_REAL_STRIPE = STRIPE_SECRET_KEY is not None and STRIPE_SECRET_KEY.startswith("sk_test_")
