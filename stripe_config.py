import stripe
import secrets
from config import STRIPE_SECRET_KEY, YOUR_DOMAIN, USE_REAL_STRIPE

if USE_REAL_STRIPE:
    stripe.api_key = STRIPE_SECRET_KEY
else:
    print("⚠️ Режим симуляции: Stripe API не используется")

def create_checkout_session(email, price_id):
    if USE_REAL_STRIPE:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": 1}],
            mode="subscription",
            success_url=YOUR_DOMAIN + "/success?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=YOUR_DOMAIN + "/cancel",
            customer_email=email
        )
        return session.url
    else:
        # Симуляция: возвращаем фейковую ссылку и сохраняем данные для теста
        fake_session_id = "cs_test_" + secrets.token_urlsafe(16)
        print(f"🔹 [Симуляция] Сессия создана: {fake_session_id}")
        return f"https://checkout.stripe.com/sim/{fake_session_id}"

def handle_webhook(payload, sig_header):
    # Оставляем пустую заглушку, т.к. в симуляции вебхук не вызывается
    return {"status": "success"}
