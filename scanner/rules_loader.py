import sys
import os
import yaml
from typing import List, Dict

class RulesLoader:
    def __init__(self, rules_dir: str = None):
        if rules_dir is None:
            # Поддержка PyInstaller: используем sys._MEIPASS если приложение упаковано
            import sys
            if getattr(sys, 'frozen', False):
                base_dir = sys._MEIPASS
            else:
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            # Правила лежат в папке scanner/rules
            self.rules_dir = os.path.join(base_dir, "scanner", "rules")
        else:
            self.rules_dir = rules_dir
        self.rules: List[Dict] = []
        self.load_rules()

    def load_rules(self):
        if not os.path.exists(self.rules_dir):
            print(f"⚠️ Папка {self.rules_dir} не найдена!")
            return

        for filename in os.listdir(self.rules_dir):
            if filename.endswith(('.yaml', '.yml')):
                filepath = os.path.join(self.rules_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = yaml.safe_load(f)
                        if data:
                            if isinstance(data, list):
                                for rule in data:
                                    self._add_rule(rule, filename)
                            else:
                                self._add_rule(data, filename)
                except Exception as e:
                    print(f"Ошибка загрузки {filepath}: {e}")

        print(f"✅ Загружено правил из YAML: {len(self.rules)}")

    def _add_rule(self, rule, filename):
        if 'tier' not in rule:
            rule['tier'] = self._infer_tier(filename)
        self.rules.append(rule)

    def _infer_tier(self, filename):
        name = filename.lower()
        if 'api1' in name or 'api2' in name or 'api3' in name:
            return 'basic'
        elif 'api4' in name or 'api5' in name:
            return 'premium'
        else:
            return 'enterprise'

    def get_rules_by_tier(self, tier: str) -> List[Dict]:
        if tier == 'basic':
            return [r for r in self.rules if r.get('tier', 'basic') == 'basic']
        elif tier == 'premium':
            return [r for r in self.rules if r.get('tier', 'basic') in ('basic', 'premium')]
        else:
            return self.rules

    def get_all_rules(self):
        """Возвращает все загруженные правила"""
        return self.rules
