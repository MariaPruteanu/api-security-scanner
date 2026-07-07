import os
import yaml
from typing import List, Dict

class RulesLoader:
    """Загрузчик правил уязвимостей из YAML-файлов"""
    
    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = rules_dir
        self.rules: List[Dict] = []
        self.load_rules()

    def load_rules(self):
        if not os.path.exists(self.rules_dir):
            print(f"⚠️ Папка {self.rules_dir} не найдена!")
            return

        for filename in os.listdir(self.rules_dir):
            if filename.endswith(".yaml") or filename.endswith(".yml"):
                filepath = os.path.join(self.rules_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        rule = yaml.safe_load(f)
                        if rule and 'id' in rule:
                            self.rules.append(rule)
                except Exception as e:
                    print(f"❌ Ошибка загрузки правила {filename}: {e}")
        
        print(f"✅ Загружено правил из YAML: {len(self.rules)}")

    def get_rules_by_type(self, condition_type: str) -> List[Dict]:
        """Получить все правила, содержащие указанный тип условия"""
        return [r for r in self.rules if any(c.get('type') == condition_type for c in r.get('conditions', []))]
