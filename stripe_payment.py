import os
import stripe

# Секретный ключ берем из переменных окружения
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "sk_test_...")

def create_checkout_session(price_id, success_url, cancel_url):
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": 1}],
            mode="subscription",
            success_url=success_url,
            cancel_url=cancel_url,
        )
        return session.url
    except Exception as e:
        print(f"Stripe error: {e}")
        return None

def create_portal_session(customer_id, return_url):
    try:
        session = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=return_url,
        )
        return session.url
    except Exception as e:
        print(f"Portal error: {e}")
        return None
