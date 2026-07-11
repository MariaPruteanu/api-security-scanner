import os
import yaml

# Определяем папку правил относительно текущего скрипта
RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")

PREMIUM_KEYWORDS = [
    "brute", "graphql_depth", "rate", "payload", "mass_assign",
    "ssrf", "consume", "race", "traversal", "cmd", "redirect",
    "verbose", "xxe", "graphql_int", "state", "cookies", "debug"
]

def determine_category(filename, data):
    name_lower = filename.lower()
    for kw in PREMIUM_KEYWORDS:
        if kw in name_lower:
            return "premium"
    if data.get("severity", "").lower() == "high":
        if "header" in name_lower or "hsts" in name_lower or "csp" in name_lower:
            return "basic"
        return "premium"
    return "basic"

def main():
    if not os.path.exists(RULES_DIR):
        print(f"Папка {RULES_DIR} не найдена.")
        return

    for filename in os.listdir(RULES_DIR):
        if not filename.endswith(('.yaml', '.yml')):
            continue
        filepath = os.path.join(RULES_DIR, filename)
        with open(filepath, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        if data is None:
            continue
        if 'category' in data:
            continue
        category = determine_category(filename, data)
        data['category'] = category
        with open(filepath, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        print(f"✅ {filename} -> category: {category}")

    print("🎉 Готово!")

if __name__ == "__main__":
    main()
