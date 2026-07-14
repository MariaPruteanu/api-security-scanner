#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Webhook Server для обработки платежей Stripe
Запускается на localhost:8000
"""
from flask import Flask, request, jsonify
from payment_processor import StripePaymentProcessor
import os
import json

app = Flask(__name__)
processor = StripePaymentProcessor()

@app.route('/webhook', methods=['POST'])
def webhook():
    """Endpoint для webhook от Stripe"""
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    webhook_secret = os.environ.get('WEBHOOK_SECRET')
    
    result = processor.handle_webhook(payload, sig_header, webhook_secret)
    
    if result['status'] == 'success':
        return jsonify({'received': True, 'license': result.get('license')})
    else:
        return jsonify({'error': result.get('message', 'Unknown error')}), 400

@app.route('/success')
def success():
    """Страница успешной оплаты"""
    session_id = request.args.get('session_id')
    
    if session_id:
        result = processor.verify_payment(session_id)
        if result['success']:
            return f"""
            <html>
            <head><title>Payment Successful!</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1 style="color: #2ecc71;">✅ Payment Successful!</h1>
                <h2>Your License Key:</h2>
                <div style="background: #f0f0f0; padding: 20px; margin: 20px; border-radius: 8px; font-family: monospace; font-size: 18px;">
                    {result['license_key']}
                </div>
                <p>License has been saved to 'license.key' and sent to {result['email']}</p>
                <p>Plan: {result['plan'].title()} ({result['period']})</p>
                <button onclick="window.close()">Close</button>
            </body>
            </html>
            """
    
    return "<h1>Payment verification failed</h1>"

@app.route('/cancel')
def cancel():
    """Страница отмены оплаты"""
    return """
    <html>
    <head><title>Payment Cancelled</title></head>
    <body style="font-family: Arial; text-align: center; padding: 50px;">
        <h1 style="color: #e74c3c;">❌ Payment Cancelled</h1>
        <p>You can try again anytime.</p>
        <button onclick="window.close()">Close</button>
    </body>
    </html>
    """

if __name__ == '__main__':
    print("🚀 Starting webhook server on http://localhost:8000")
    print("Webhook URL for Stripe: http://localhost:8000/webhook")
    app.run(host='0.0.0.0', port=8000, debug=True)
