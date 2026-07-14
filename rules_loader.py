import os
import yaml
from typing import List, Dict, Any

class RulesLoader:
    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = rules_dir

    def get_rules_by_tier(self, tier: str = "basic") -> List[Dict[str, Any]]:
        """
        Загружает правила в зависимости от тарифа:
        - basic (Free) → free_rules.yaml
        - premium → default.yaml (все правила)
        - enterprise → default.yaml (все правила)
        """
        if tier == "basic":
            filename = "free_rules.yaml"
        else:
            filename = "default.yaml"

        filepath = os.path.join(self.rules_dir, filename)
        if not os.path.exists(filepath):
            # fallback: если файла нет, загружаем default
            filepath = os.path.join(self.rules_dir, "default.yaml")

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                rules = yaml.safe_load(f)
                if not rules:
                    return []
                return rules
        except Exception as e:
            print(f"⚠️ Ошибка загрузки правил: {e}")
            return []
