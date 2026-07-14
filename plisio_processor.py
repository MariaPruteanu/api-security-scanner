#!/usr/bin/env python3
import os
import requests
import json
from payment import PaymentManager

class PlisioProcessor:
    def __init__(self):
        self.api_key = os.environ.get('PLISIO_API_KEY')
        self.base_url = 'https://plisio.net/api/v1'
        self.pm = PaymentManager()
        self.prices = {
            'premium': {'monthly': 9.99, 'yearly': 99.99},
            'enterprise': {'monthly': 29.99, 'yearly': 299.99}
        }
        self.app_url = os.environ.get('NGROK_URL', os.environ.get('APP_URL', 'http://localhost:8001'))
    
    def create_invoice(self, plan: str, period: str, email: str) -> dict:
        amount = self.prices[plan][period]
        order_number = f"{plan}_{period}_{email}_{os.urandom(4).hex()}"
        
        payload = {
            'api_key': self.api_key,
            'amount': amount,
            'currency': 'USD',
            'order_number': order_number,
            'source_currency': 'USDT_TRX',
            'source_amount': amount,
            'description': f'API Security Scanner Pro - {plan.title()} ({period})',
            'email': email,
            'callback_url': f'{self.app_url}/crypto/callback',
            'success_url': f'{self.app_url}/crypto/success?order_id={order_number}',
            'cancel_url': f'{self.app_url}/crypto/cancel',
            'metadata': json.dumps({'plan': plan, 'period': period, 'email': email})
        }
        
        try:
            response = requests.post(f'{self.base_url}/invoices/new', data=payload)
            result = response.json()
            if result.get('status') == 'success':
                data = result.get('data', {})
                return {'success': True, 'url': data.get('invoice_url'), 'order_id': order_number, 'amount': amount}
            else:
                return {'success': False, 'error': result.get('data', {}).get('error', 'Unknown error')}
        except Exception as e:
            return {'success': False, 'error': str(e)}
