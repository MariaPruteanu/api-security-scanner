#!/usr/bin/env python3
import os
import hashlib
import hmac

class PaddleProcessor:
    """Обработка платежей через Paddle"""
    
    def __init__(self):
        self.vendor_id = os.environ.get('PADDLE_VENDOR_ID', '12345')
        self.api_key = os.environ.get('PADDLE_API_KEY', 'test_key')
        self.environment = os.environ.get('PADDLE_ENV', 'sandbox')  # sandbox или production
        
        self.prices = {
            'premium': {
                'monthly': {'USD': 9.99, 'RUB': 899},
                'yearly': {'USD': 99.99, 'RUB': 8999}
            },
            'enterprise': {
                'monthly': {'USD': 29.99, 'RUB': 2799},
                'yearly': {'USD': 299.99, 'RUB': 27999}
            }
        }
    
    def generate_checkout_url(self, plan: str, period: str, email: str, currency: str = 'USD') -> str:
        """
        Генерирует ссылку на оплату Paddle
        """
        price = self.prices[plan][period].get(currency, self.prices[plan][period]['USD'])
        
        # Paddle Checkout URL (в реальности нужно создавать через API)
        # Для демо используем прямой формат
        checkout_url = (
            f"https://sandbox-checkout.paddle.com/checkout/custom?"
            f"vendor_id={self.vendor_id}&"
            f"title=API Security Scanner Pro - {plan.title()} ({period})&"
            f"message=License for {email}&"
            f"prices[{currency}]={int(price * 100)}&"
            f"customer_email={email}&"
            f"passthrough={plan}_{period}_{email}"
        )
        
        return checkout_url
    
    def verify_webhook(self, payload: dict, signature: str) -> bool:
        """Проверяет webhook от Paddle"""
        # В production здесь проверка подписи
        return True
    
    def handle_payment_completed(self, order_data: dict):
        """Обработка успешной оплаты"""
        email = order_data.get('email')
        passthrough = order_data.get('passthrough', '')
        
        # Извлекаем plan и period из passthrough
        parts = passthrough.split('_')
        plan = parts[0]
        period = parts[1]
        
        # Генерируем лицензию
        from payment import PaymentManager
        pm = PaymentManager()
        license_key = pm.generate_license_key(plan, period, email)
        pm.save_license(license_key, plan, period, email)
        
        return {
            'success': True,
            'license_key': license_key,
            'plan': plan,
            'period': period
        }
