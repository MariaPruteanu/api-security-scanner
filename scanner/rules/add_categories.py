import os
import yaml

# Путь к папке с правилами (относительно корня проекта)
RULES_DIR = "rules"

# Ключевые слова, по которым определяем Premium-правила
PREMIUM_KEYWORDS = [
    "brute", "graphql_depth", "rate", "payload", "mass_assign",
    "ssrf", "consume", "race", "traversal", "cmd", "redirect",
    "verbose", "xxe", "graphql_int", "state", "cookies", "debug"
]

def determine_category(filename, data):
    """
    Определяет категорию правила.
    Возвращает 'basic' или 'premium'.
    """
    name_lower = filename.lower()
    # Если в названии есть премиум-ключевое слово
    for kw in PREMIUM_KEYWORDS:
        if kw in name_lower:
            return "premium"
    # Если в данных есть поле severity == 'high' и оно не относится к простым заголовкам
    # (можно добавить дополнительные проверки)
    if data.get("severity", "").lower() == "high":
        # Проверим, не относится ли к базовым (например, если id содержит "headers" или "hsts")
        if "header" in name_lower or "hsts" in name_lower or "csp" in name_lower:
            return "basic"
        return "premium"
    # По умолчанию – basic
    return "basic"

def main():
    if not os.path.exists(RULES_DIR):
        print(f"Папка {RULES_DIR} не найдена. Убедитесь, что скрипт запускается из корня проекта.")
        return

    for filename in os.listdir(RULES_DIR):
        if not filename.endswith(('.yaml', '.yml')):
            continue

        filepath = os.path.join(RULES_DIR, filename)
        with open(filepath, 'r', encoding='utf-8') as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                print(f"❌ Ошибка парсинга {filename}: {e}")
                continue

        if data is None:
            print(f"⚠️ {filename} пуст или не является словарём, пропускаем.")
            continue

        # Если category уже есть – пропускаем
        if 'category' in data:
            continue

        # Определяем категорию
        category = determine_category(filename, data)
        data['category'] = category

        # Сохраняем обратно, сохраняя форматирование
        with open(filepath, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

        print(f"✅ {filename} -> category: {category}")

    print("🎉 Все правила обновлены!")

if __name__ == "__main__":
    main()
