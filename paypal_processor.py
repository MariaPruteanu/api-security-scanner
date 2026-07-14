#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PayPal Payment Processor
Обработка платежей через PayPal
"""
import os
import paypalrestsdk
from payment import PaymentManager

class PayPalProcessor:
    """Обработчик платежей PayPal"""
    
    def __init__(self, mode='sandbox'):
        self.pm = PaymentManager()
        
        # Настройки PayPal
        paypalrestsdk.configure({
            "mode": mode,  # sandbox или live
            "client_id": os.environ.get('PAYPAL_CLIENT_ID'),
            "client_secret": os.environ.get('PAYPAL_CLIENT_SECRET')
        })
        
        self.prices = {
            'premium': {
                'monthly': {'USD': '9.99', 'RUB': '899'},
                'yearly': {'USD': '99.99', 'RUB': '8999'}
            },
            'enterprise': {
                'monthly': {'USD': '29.99', 'RUB': '2799'},
                'yearly': {'USD': '299.99', 'RUB': '27999'}
            }
        }
    
    def create_payment(self, plan: str, period: str, email: str, currency: str = 'USD') -> dict:
        """
        Создает платеж PayPal
        Возвращает approval_url для перенаправления пользователя
        """
        amount = self.prices[plan][period].get(currency, self.prices[plan][period]['USD'])
        currency_code = 'USD' if currency == 'USD' else 'RUB'
        
        payment = paypalrestsdk.Payment({
            "intent": "sale",
            "payer": {
                "payment_method": "paypal"
            },
            "redirect_urls": {
                "return_url": f"{os.environ.get('APP_URL', 'http://localhost:8000')}/paypal/success?plan={plan}&period={period}&email={email}&amount={amount}&currency={currency_code}",
                "cancel_url": f"{os.environ.get('APP_URL', 'http://localhost:8000')}/paypal/cancel"
            },
            "transactions": [{
                "item_list": {
                    "items": [{
                        "name": f"API Security Scanner Pro - {plan.title()} ({period})",
                        "description": f"License for {email}\nIncludes: All security rules, Rule Manager, Reports",
                        "quantity": "1",
                        "currency": currency_code,
                        "price": amount
                    }]
                },
                "amount": {
                    "total": amount,
                    "currency": currency_code
                },
                "description": f"API Scanner Pro License - {plan.title()}",
                "custom": f"{plan}_{period}_{email}"
            }]
        })
        
        if payment.create():
            # Находим URL для одобрения платежа
            for link in payment.links:
                if link.rel == "approval_url":
                    approval_url = str(link.href)
                    return {
                        'success': True,
                        'approval_url': approval_url,
                        'payment_id': payment.id
                    }
            
            return {'success': False, 'error': 'No approval URL found'}
        else:
            return {'success': False, 'error': payment.error}
    
    def execute_payment(self, payment_id: str, payer_id: str, plan: str, period: str, email: str) -> dict:
        """
        Выполняет платеж после одобрения пользователем
        """
        payment = paypalrestsdk.Payment.find(payment_id)
        
        if payment.execute({"payer_id": payer_id}):
            # Платеж успешен - генерируем лицензию
            license_key = self.pm.generate_license_key(plan, period, email)
            self.pm.save_license(license_key, plan, period, email)
            
            return {
                'success': True,
                'license_key': license_key,
                'plan': plan,
                'period': period,
                'email': email
            }
        else:
            return {'success': False, 'error': payment.error}
    
    def get_checkout_url(self, plan: str, period: str, email: str, currency: str = 'USD') -> str:
        """
        Создает и возвращает URL для оплаты
        """
        result = self.create_payment(plan, period, email, currency)
        if result['success']:
            return result['approval_url']
        else:
            raise Exception(f"PayPal error: {result['error']}")
