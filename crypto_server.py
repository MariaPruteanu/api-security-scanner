#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cryptomus Return Handler
Обрабатывает возврат после оплаты
"""
from flask import Flask, request, jsonify, render_template_string
from cryptomus_processor import CryptomusProcessor
import os

app = Flask(__name__)
processor = CryptomusProcessor()

@app.route('/crypto/success')
def crypto_success():
    """Страница успешной оплаты"""
    order_id = request.args.get('order_id')
    
    if order_id:
        # Проверяем статус платежа
        result = processor.check_payment_status(order_id)
        
        if result.get('success') and result.get('status') == 'paid':
            return render_template_string("""
            <html>
            <head>
                <title>Payment Successful!</title>
                <style>
                    body { 
                        font-family: 'Segoe UI', Arial, sans-serif; 
                        text-align: center; 
                        padding: 50px; 
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        min-height: 100vh;
                        margin: 0;
                    }
                    .container { 
                        background: white; 
                        padding: 50px; 
                        border-radius: 15px; 
                        max-width: 600px; 
                        margin: 0 auto; 
                        box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    }
                    h1 { color: #2ecc71; font-size: 48px; margin-bottom: 20px; }
                    h2 { color: #2c3e50; margin-bottom: 30px; }
                    .license { 
                        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                        padding: 25px; 
                        margin: 30px 0; 
                        border-radius: 10px; 
                        font-family: 'Courier New', monospace; 
                        font-size: 20px; 
                        color: white;
                        font-weight: bold;
                        word-break: break-all;
                        box-shadow: 0 5px 15px rgba(0,0,0,0.2);
                    }
                    .info { 
                        color: #666; 
                        margin: 15px 0; 
                        font-size: 16px;
                        line-height: 1.6;
                    }
                    .badge {
                        display: inline-block;
                        background: #3498db;
                        color: white;
                        padding: 8px 20px;
                        border-radius: 20px;
                        margin: 5px;
                        font-weight: bold;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>✅ Payment Successful!</h1>
                    <h2>Thank you for your purchase!</h2>
                    
                    <div>
                        <span class="badge">{{ plan.title() }}</span>
                        <span class="badge">{{ period }}</span>
                    </div>
                    
                    <div class="info">
                        <p><strong>Email:</strong> {{ email }}</p>
                        <p><strong>Amount paid:</strong> ${{ "%.2f"|format(amount) }} USDT</p>
                    </div>
                    
                    <h3>Your License Key:</h3>
                    <div class="license">{{ license_key }}</div>
                    
                    <div class="info">
                        <p>✅ License has been saved to <strong>'license.key'</strong></p>
                        <p>✅ A confirmation has been sent to <strong>{{ email }}</strong></p>
                        <p>✅ You can now use all {{ plan.title() }} features</p>
                    </div>
                    
                    <button onclick="window.close()" 
                            style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                                   color: white; 
                                   border: none; 
                                   padding: 18px 40px; 
                                   border-radius: 8px; 
                                   font-size: 18px; 
                                   cursor: pointer; 
                                   margin-top: 30px;
                                   font-weight: bold;">
                        Close Window
                    </button>
                </div>
            </body>
            </html>
            """, **result, amount=float(order_id.split('_')[2]) if '_' in order_id else 0)
        else:
            return "<h1>⏳ Payment Pending</h1><p>Please wait for confirmation or contact support.</p>"
    
    return "<h1> Invalid Payment</h1><p>Missing payment details</p>"

@app.route('/crypto/callback', methods=['POST'])
def crypto_callback():
    """Webhook для автоматического подтверждения"""
    data = request.json
    
    # Здесь можно добавить проверку подписи
    order_id = data.get('order_id')
    status = data.get('status')
    
    if status == 'payed':
        # Автоматически генерируем лицензию
        result = processor.check_payment_status(order_id)
        if result.get('success'):
            print(f"✅ License generated: {result['license_key']}")
            # Здесь можно отправить email
    
    return jsonify({'state': 1})

@app.route('/crypto/cancel')
def crypto_cancel():
    """Страница отмены оплаты"""
    return render_template_string("""
    <html>
    <head>
        <title>Payment Cancelled</title>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                text-align: center; 
                padding: 50px; 
                background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                min-height: 100vh;
                margin: 0;
            }
            .container { 
                background: white; 
                padding: 50px; 
                border-radius: 15px; 
                max-width: 600px; 
                margin: 0 auto; 
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            }
            h1 { color: #e74c3c; font-size: 48px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>❌ Payment Cancelled</h1>
            <p>You have cancelled the payment.</p>
            <p>You can try again anytime.</p>
            <button onclick="window.close()" 
                    style="background: #e74c3c; 
                           color: white; 
                           border: none; 
                           padding: 15px 30px; 
                           border-radius: 6px; 
                           font-size: 16px; 
                           cursor: pointer; 
                           margin-top: 20px;">
                Close
            </button>
        </div>
    </body>
    </html>
    """)

if __name__ == '__main__':
    print(" Starting Cryptomus payment handler on http://localhost:8000")
    print("Return URLs:")
    print("  - Success:  http://localhost:8000/crypto/success")
    print("  - Cancel:   http://localhost:8000/crypto/cancel")
    print("  - Callback: http://localhost:8000/crypto/callback")
    app.run(host='0.0.0.0', port=8000, debug=True)
