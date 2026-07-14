import os, json, uuid, hashlib
from datetime import datetime, timedelta
from typing import Dict

PRICING = {
    'premium': {'monthly': {'usd': 9.99, 'rub': 899}, 'yearly': {'usd': 99.99, 'rub': 8999, 'discount': '17%'}},
    'enterprise': {'monthly': {'usd': 29.99, 'rub': 2799}, 'yearly': {'usd': 299.99, 'rub': 27999, 'discount': '17%'}}
}

class PaymentManager:
    def __init__(self):
        self.licenses_file = os.path.join(os.path.expanduser("~"), ".apiscanner_licenses.json")
    def generate_license_key(self, plan: str, period: str, email: str) -> str:
        ts = datetime.now().strftime("%Y%m%d")
        rnd = uuid.uuid4().hex[:8].upper()
        hsh = hashlib.md5(email.encode()).hexdigest()[:6].upper()
        p_code = {'premium': 'PRO', 'enterprise': 'ENT'}[plan]
        per_code = {'monthly': 'M', 'yearly': 'Y'}[period]
        return f"{p_code}-{per_code}-{ts}-{hsh}-{rnd}"
    def get_expiry_date(self, period: str) -> str:
        days = 30 if period == 'monthly' else 365
        return (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
    def save_license(self, key: str, plan: str, period: str, email: str):
        licenses = self._load_licenses()
        licenses[key] = {'plan': plan, 'period': period, 'email': email, 'created': datetime.now().isoformat(), 'expires': self.get_expiry_date(period), 'active': True}
        with open(self.licenses_file, 'w', encoding='utf-8') as f: json.dump(licenses, f, ensure_ascii=False, indent=2)
        lic_file = 'license.key' if os.path.exists('license.key') else os.path.join(os.path.dirname(__file__), 'license.key')
        with open(lic_file, 'w', encoding='utf-8') as f: f.write(key)
    def _load_licenses(self) -> Dict:
        if os.path.exists(self.licenses_file):
            try:
                with open(self.licenses_file, 'r', encoding='utf-8') as f: return json.load(f)
            except: pass
        return {}
