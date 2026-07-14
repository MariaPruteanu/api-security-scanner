#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PayPal Return Handler
Обрабатывает возврат от PayPal после оплаты
"""
from flask import Flask, request, jsonify, render_template_string
from paypal_processor import PayPalProcessor
import os

app = Flask(__name__)
processor = PayPalProcessor(mode=os.environ.get('PAYPAL_MODE', 'sandbox'))

@app.route('/paypal/success')
def paypal_success():
    """Обработка успешной оплаты"""
    payment_id = request.args.get('paymentId')
    payer_id = request.args.get('PayerID')
    plan = request.args.get('plan')
    period = request.args.get('period')
    email = request.args.get('email')
    amount = request.args.get('amount')
    currency = request.args.get('currency')
    
    if payment_id and payer_id:
        result = processor.execute_payment(payment_id, payer_id, plan, period, email)
        
        if result['success']:
            return render_template_string("""
            <html>
            <head>
                <title>Payment Successful!</title>
                <style>
                    body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
                    .container { background: white; padding: 40px; border-radius: 12px; max-width: 600px; margin: 0 auto; box-shadow: 0 10px 40px rgba(0,0,0,0.2); }
                    h1 { color: #2ecc71; }
                    .license { background: #f0f0f0; padding: 20px; margin: 20px 0; border-radius: 8px; font-family: monospace; font-size: 18px; word-break: break-all; }
                    .info { color: #666; margin: 10px 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>✅ Payment Successful!</h1>
                    <h2>Thank you for your purchase!</h2>
                    <div class="info">
                        <p><strong>Plan:</strong> {{ plan.title() }} ({{ period }})</p>
                        <p><strong>Email:</strong> {{ email }}</p>
                        <p><strong>Amount:</strong> {{ currency }} {{ amount }}</p>
                    </div>
                    <h3>Your License Key:</h3>
                    <div class="license">{{ license_key }}</div>
                    <p>License has been saved to <strong>'license.key'</strong></p>
                    <p>A confirmation email will be sent to {{ email }}</p>
                    <button onclick="window.close()" style="background: #0070ba; color: white; border: none; padding: 15px 30px; border-radius: 6px; font-size: 16px; cursor: pointer; margin-top: 20px;">Close</button>
                </div>
            </body>
            </html>
            """, **result)
        else:
            return f"<h1>Payment Verification Failed</h1><p>Error: {result['error']}</p>"
    
    return "<h1>Invalid Payment</h1><p>Missing payment details</p>"

@app.route('/paypal/cancel')
def paypal_cancel():
    """Обработка отмены оплаты"""
    return render_template_string("""
    <html>
    <head>
        <title>Payment Cancelled</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
            .container { background: white; padding: 40px; border-radius: 12px; max-width: 600px; margin: 0 auto; box-shadow: 0 10px 40px rgba(0,0,0,0.2); }
            h1 { color: #e74c3c; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>❌ Payment Cancelled</h1>
            <p>You have cancelled the payment.</p>
            <p>You can try again anytime.</p>
            <button onclick="window.close()" style="background: #e74c3c; color: white; border: none; padding: 15px 30px; border-radius: 6px; font-size: 16px; cursor: pointer; margin-top: 20px;">Close</button>
        </div>
    </body>
    </html>
    """)

if __name__ == '__main__':
    print("🚀 Starting PayPal return handler on http://localhost:8000")
    print("Return URLs:")
    print("  - Success: http://localhost:8000/paypal/success")
    print("  - Cancel:  http://localhost:8000/paypal/cancel")
    app.run(host='0.0.0.0', port=8000, debug=True)
