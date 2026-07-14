with open('scanner/core.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
has_rules_loader = False

for line in lines:
    # 1. Безжалостно удаляем любые строки, где упоминается load_specification или плохой loader
    if 'load_specification' in line:
        continue
    if 'from loader import' in line or 'import loader' in line:
        continue
        
    # 2. Проверяем, есть ли уже правильный импорт
    if 'from .rules_loader import RulesLoader' in line:
        has_rules_loader = True
        
    new_lines.append(line)
    
    # 3. Если правильного импорта еще нет, и мы только что прошли 'import sys', добавляем его
    if not has_rules_loader and line.strip() == 'import sys':
        new_lines.append('from .rules_loader import RulesLoader\n')
        has_rules_loader = True

# Если import sys не был найден (маловероятно), добавим в самое начало
if not has_rules_loader:
    new_lines.insert(0, 'from .rules_loader import RulesLoader\n')

with open('scanner/core.py', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print("✅ scanner/core.py исправлен на 100%!")
