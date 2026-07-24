import sys
import re

filename = "main_window.py"
with open(filename, 'r') as f:
    content = f.read()

# Находим проблемный блок и заменяем его
pattern = r'(formatted = \[\]\s*for item in raw_results:.*?self\.log\(f"📊 Преобразовано записей:)'
# Просто заменим весь проблемный участок на правильный
# Используем более простой подход: находим строки и заменяем

lines = content.split('\n')
new_lines = []
i = 0
while i < len(lines):
    line = lines[i]
    if 'formatted = []' in line:
        # Пропускаем всё до self.log
        new_lines.append('                formatted = []')
        i += 1
        # Пропускаем старые строки до self.log
        while i < len(lines) and 'self.log(f"📊 Преобразовано записей:' not in lines[i]:
            i += 1
        # Вставляем правильный блок
        new_lines.extend([
            '                for item in raw_results:',
            '                    if isinstance(item, dict):',
            '                        desc = item.get("description") or item.get("message") or f"{item.get(\'vulnerability\', \'\')} {item.get(\'evidence\', \'\')} {item.get(\'recommendation\', \'\')}".strip()',
            '                        if not desc:',
            '                            desc = str(item)',
            '                        formatted.append({',
            '                            \'id\': item.get(\'id\', str(len(formatted) + 1)),',
            '                            \'severity\': item.get(\'severity\', \'\'),',
            '                            \'description\': desc',
            '                        })',
            '                    else:',
            '                        desc = getattr(item, \'description\', \'\') or getattr(item, \'message\', \'\') or str(item)',
            '                        formatted.append({',
            '                            \'id\': getattr(item, \'id\', str(len(formatted) + 1)),',
            '                            \'severity\': getattr(item, \'severity\', \'\'),',
            '                            \'description\': desc',
            '                        })',
        ])
        # Пропускаем старый self.log и вставляем новый
        while i < len(lines) and 'self.log(f"📊 Преобразовано записей:' not in lines[i]:
            i += 1
        if i < len(lines):
            new_lines.append(lines[i])  # оставляем self.log
            i += 1
        continue
    else:
        new_lines.append(line)
        i += 1

with open(filename, 'w') as f:
    f.write('\n'.join(new_lines))

print("Файл исправлен")
