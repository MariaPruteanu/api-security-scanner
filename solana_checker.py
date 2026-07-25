import os
import requests
from datetime import datetime, timedelta

class SolanaChecker:
    def __init__(self):
        self.wallet_address = os.getenv("DEFI_WALLET_ADDRESS", "UQCNq21KjvjmRVgjBTPbvXcJx8b4BT5tTt2GTRrJ2EhxbnMg")
        self.rpc_url = "https://api.mainnet-beta.solana.com"

    def get_recent_transactions(self, limit=20):
        try:
            url = f"https://public-api.solscan.io/account/{self.wallet_address}/transactions?limit={limit}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                return resp.json()
            return []
        except Exception as e:
            print(f"Solscan error: {e}")
            return []

    def check_payment(self, expected_amount=9, token="USDT"):
        try:
            tx_list = self.get_recent_transactions(limit=20)
            if not tx_list:
                return False, None, "No recent transactions found. Please send USDT and try again."

            now = datetime.now()
            for tx in tx_list:
                tx_time = datetime.fromtimestamp(tx.get('blockTime', 0))
                if (now - tx_time) > timedelta(minutes=10):
                    continue

                # Проверяем, есть ли USDT в транзакции (упрощённо)
                if 'USDT' in str(tx) or 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v' in str(tx):
                    return True, tx.get('signature', 'unknown'), "Payment found! License activated."
            
            return False, None, "No USDT payment found in the last 10 minutes. Please check your transaction."
        except Exception as e:
            return False, None, f"Error checking Solana: {e}"

checker = SolanaChecker()
