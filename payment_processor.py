#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Stripe Payment Processor
Обработка платежей через Stripe
"""
import os
import stripe
from datetime import datetime
from typing import Optional, Dict
from payment import PaymentManager

# Инициализация Stripe
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_PUBLIC_KEY = os.environ.get('STRIPE_PUBLIC_KEY', '')

class StripePaymentProcessor:
    """Обработчик платежей Stripe"""
    
    def __init__(self):
        self.pm = PaymentManager()
        self.prices = {
            'premium': {
                'monthly': {'usd': 999, 'rub': 89900},  # В центах/копейках
                'yearly': {'usd': 9999, 'rub': 899900}
            },
            'enterprise': {
                'monthly': {'usd': 2999, 'rub': 279900},
                'yearly': {'usd': 29999, 'rub': 2799900}
            }
        }
    
    def create_checkout_session(self, plan: str, period: str, email: str, currency: str = 'usd') -> str:
        """
        Создает сессию оплаты Stripe
        Возвращает URL для оплаты
        """
        try:
            price_amount = self.prices[plan][period].get(currency, self.prices[plan][period]['usd'])
            
            # Создаем checkout сессию
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': currency,
                        'product_data': {
                            'name': f'API Security Scanner Pro - {plan.title()} ({period})',
                            'description': f'License for {email}\nIncludes: All security rules, Rule Manager, Reports',
                            'images': ['https://apiscanner.pro/logo.png']  # Замени на свой логотип
                        },
                        'unit_amount': price_amount,
                    },
                    'quantity': 1,
                }],
                mode='payment',
                success_url=f'{os.environ.get("APP_URL", "http://localhost:8000")}/success?session_id={{CHECKOUT_SESSION_ID}}',
                cancel_url=f'{os.environ.get("APP_URL", "http://localhost:8000")}/cancel',
                customer_email=email,
                client_reference_id=f"{plan}_{period}_{email}",
                metadata={
                    'plan': plan,
                    'period': period,
                    'email': email,
                    'currency': currency
                }
            )
            
            return session.url
            
        except stripe.error.StripeError as e:
            print(f"Stripe error: {e}")
            raise Exception(f"Payment error: {str(e)}")
    
    def verify_payment(self, session_id: str) -> Optional[Dict]:
        """
        Проверяет статус оплаты и генерирует лицензию
        """
        try:
            session = stripe.checkout.Session.retrieve(session_id)
            
            if session.payment_status == 'paid':
                # Извлекаем данные из metadata
                metadata = session.metadata
                plan = metadata.get('plan')
                period = metadata.get('period')
                email = metadata.get('email')
                currency = metadata.get('currency', 'usd')
                
                # Генерируем лицензионный ключ
                license_key = self.pm.generate_license_key(plan, period, email)
                
                # Сохраняем лицензию
                self.pm.save_license(license_key, plan, period, email)
                
                # Здесь можно отправить email с ключом
                # self.send_license_email(email, license_key, plan, period)
                
                return {
                    'success': True,
                    'license_key': license_key,
                    'plan': plan,
                    'period': period,
                    'email': email
                }
            else:
                return {'success': False, 'error': 'Payment not completed'}
                
        except stripe.error.StripeError as e:
            print(f"Verification error: {e}")
            return {'success': False, 'error': str(e)}
    
    def handle_webhook(self, payload: str, sig_header: str, webhook_secret: str) -> Dict:
        """
        Обработка webhook от Stripe
        """
        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, webhook_secret
            )
            
            # Обрабатываем разные типы событий
            if event['type'] == 'checkout.session.completed':
                session = event['data']['object']
                # Генерируем лицензию
                result = self.verify_payment(session.id)
                if result['success']:
                    # Отправляем email или делаем другие действия
                    print(f"License generated: {result['license_key']}")
                    return {'status': 'success', 'license': result}
            
            return {'status': 'ignored'}
            
        except stripe.error.SignatureVerificationError:
            return {'status': 'error', 'message': 'Invalid signature'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def send_license_email(self, email: str, key: str, plan: str, period: str):
        """
        Отправляет email с лицензионным ключом
        (Здесь можно подключить SendGrid, Mailgun и т.д.)
        """
        # Пример с использованием smtplib или requests к email API
        print(f"Sending license {key} to {email}")
        # TODO: Реализовать отправку email
        pass

# Helper function для создания сессии
def create_payment_link(plan: str, period: str, email: str, currency: str = 'usd') -> str:
    """Создает ссылку на оплату"""
    processor = StripePaymentProcessor()
    return processor.create_checkout_session(plan, period, email, currency)
