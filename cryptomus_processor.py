#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cryptomus Payment Processor
Прием платежей через криптовалюты (работает с РФ)
"""
import os
import requests
import hashlib
import json
from payment import PaymentManager

class CryptomusProcessor:
    def __init__(self):
        self.merchant_id = os.environ.get('CRYPTOMUS_MERCHANT_ID')
        self.api_key = os.environ.get('CRYPTOMUS_API_KEY')
        self.base_url = 'https://api.cryptomus.com/v1'
        self.pm = PaymentManager()
        
        # Цены в USD (криптовалюта привязана к USD)
        self.prices = {
            'premium': {'monthly': 9.99, 'yearly': 99.99},
            'enterprise': {'monthly': 29.99, 'yearly': 299.99}
        }
    
    def _generate_sign(self, data: dict) -> str:
        """Генерирует подпись для запроса"""
        sorted_data = json.dumps(data, separators=(',', ':'))
        sign = hashlib.md5((sorted_data + self.api_key).encode()).hexdigest()
        return sign.upper()
    
    def create_payment(self, plan: str, period: str, email: str) -> dict:
        """
        Создает платеж в Cryptomus
        Возвращает URL для оплаты
        """
        amount = self.prices[plan][period]
        order_id = f"{plan}_{period}_{email}_{os.urandom(4).hex()}"
        
        # Данные для запроса
        payload = {
            "amount": str(amount),
            "currency": "USDT",  # Можно изменить на BTC, TON, ETH
            "order_id": order_id,
            "url_return": os.environ.get('APP_URL', 'http://localhost:8000') + '/crypto/success',
            "url_callback": os.environ.get('APP_URL', 'http://localhost:8000') + '/crypto/callback',
            "is_payment_multiple": False,
            "to_currency": False,  # Пользователь платит точно в USDT
            "metadata": json.dumps({
                "plan": plan,
                "period": period,
                "email": email
            })
        }
        
        # Добавляем подпись
        headers = {
            "merchant": self.merchant_id,
            "sign": self._generate_sign(payload)
        }
        
        try:
            response = requests.post(
                f'{self.base_url}/payment',
                json=payload,
                headers=headers
            )
            
            result = response.json()
            
            if result.get('state') == 1:
                return {
                    'success': True,
                    'url': result['result']['url'],
                    'order_id': order_id,
                    'amount': amount
                }
            else:
                return {
                    'success': False,
                    'error': result.get('message', 'Unknown error')
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def check_payment_status(self, order_id: str) -> dict:
        """Проверяет статус платежа"""
        payload = {"order_id": order_id}
        
        headers = {
            "merchant": self.merchant_id,
            "sign": self._generate_sign(payload)
        }
        
        try:
            response = requests.post(
                f'{self.base_url}/payment/info',
                json=payload,
                headers=headers
            )
            
            result = response.json()
            
            if result.get('state') == 1:
                payment_info = result.get('result', {})
                status = payment_info.get('status')
                
                # Статусы: wait, payed, cancel, fail
                if status == 'payed':
                    # Платеж прошел - генерируем лицензию
                    metadata = json.loads(payment_info.get('metadata', '{}'))
                    plan = metadata.get('plan')
                    period = metadata.get('period')
                    email = metadata.get('email')
                    
                    license_key = self.pm.generate_license_key(plan, period, email)
                    self.pm.save_license(license_key, plan, period, email)
                    
                    return {
                        'success': True,
                        'status': 'paid',
                        'license_key': license_key,
                        'plan': plan,
                        'period': period,
                        'email': email
                    }
                else:
                    return {
                        'success': False,
                        'status': status
                    }
            else:
                return {
                    'success': False,
                    'error': result.get('message', 'Unknown error')
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
