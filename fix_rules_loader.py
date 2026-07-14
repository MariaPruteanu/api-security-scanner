with open('scanner/rules_loader.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Добавляем метод get_all_rules в конец класса RulesLoader
if 'def get_all_rules' not in content:
    # Находим последний метод или конец класса и добавляем новый
    content += '\n    def get_all_rules(self):\n        """Возвращает все загруженные правила"""\n        return self.rules\n'
    
    with open('scanner/rules_loader.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("✅ Метод get_all_rules() добавлен в RulesLoader!")
else:
    print("✅ Метод уже существует.")
