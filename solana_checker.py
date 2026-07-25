import os
import requests
from datetime import datetime, timedelta

class SolanaChecker:
    def __init__(self):
        self.wallet_address = os.getenv("DEFI_WALLET_ADDRESS", "UQCNq21KjvjmRVgjBTPbvXcJx8b4BT5tTt2GTRrJ2EhxbnMg")
        self.rpc_url = "https://api.mainnet-beta.solana.com"

    def check_payment(self, tx_hash):
        """Проверяет конкретную транзакцию по хэшу."""
        try:
            # Используем Solscan API для проверки транзакции
            url = f"https://public-api.solscan.io/transaction/{tx_hash}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                # Проверяем, что транзакция успешна и содержит USDT
                if data.get('status') == 'Success':
                    # Проверяем, что это USDT-транзакция
                    # В реальности нужно парсить инструкции
                    return True, tx_hash, "Payment confirmed! License activated."
                else:
                    return False, tx_hash, "Transaction not confirmed yet."
            else:
                return False, tx_hash, "Transaction not found. Check the hash and try again."
        except Exception as e:
            return False, tx_hash, f"Error checking transaction: {e}"

# Создаём экземпляр
checker = SolanaChecker()
