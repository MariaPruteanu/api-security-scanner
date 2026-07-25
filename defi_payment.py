import os
import json
from datetime import datetime

class DeFiPayment:
    def __init__(self):
        self.wallet_address = os.getenv("DEFI_WALLET_ADDRESS", "UQCNq21KjvjmRVgjBTPbvXcJx8b4BT5tTt2GTRrJ2EhxbnMg")
        self.network = "solana"
        self.token = "USDT"
        self.plans = {
            "monthly": {"usdt": 9, "rub": 810},
            "yearly": {"usdt": 99, "rub": 8910}
        }

    def get_payment_info(self, plan="monthly"):
        if plan not in self.plans:
            plan = "monthly"
        amount = self.plans[plan]["usdt"]
        # Применяем скидку 25% для годового плана
        if plan == "yearly":
            amount = round(amount * 0.75, 2)
        return {
            "wallet": self.wallet_address,
            "network": self.network,
            "token": self.token,
            "amount": amount,
            "plan": plan,
            "memo": f"API-Scanner-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        }

# Создаём экземпляр
defi = DeFiPayment()
