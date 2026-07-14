with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

fixed_lines = []
i = 0
while i < len(lines):
    line = lines[i]
    fixed_lines.append(line)
    
    # Если нашли try без отступа (внутри метода), проверяем, есть ли except
    if line.strip().startswith('try:') and i + 1 < len(lines):
        # Ищем следующий except или finally
        has_except = False
        has_finally = False
        j = i + 1
        while j < len(lines) and j < i + 50:  # Ищем в пределах 50 строк
            next_line = lines[j]
            if next_line.strip().startswith('except'):
                has_except = True
                break
            elif next_line.strip().startswith('finally'):
                has_finally = True
                break
            elif next_line.strip().startswith('def ') or next_line.strip().startswith('class '):
                # Начался новый метод или класс
                break
            j += 1
        
        # Если нет except и finally, добавляем
        if not has_except and not has_finally:
            # Добавляем except блок
            indent = ' ' * 8  # Стандартный отступ для except
            fixed_lines.append(f"{indent}except Exception as e:\n")
            fixed_lines.append(f"{indent}    print(f'Ошибка: {{e}}', file=sys.stderr)\n")
    
    i += 1

with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
    f.writelines(fixed_lines)

print("✅ Попытка исправить try/except блоки завершена!")
