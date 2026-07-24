import re

filename = "main_window.py"

with open(filename, 'r') as f:
    content = f.read()

# Если есть блок if __name__ == "__main__": заменяем его на прямой вызов run()
pattern = r'if __name__ == ["\']__main__["\']:'
if re.search(pattern, content):
    # Заменяем строку с условием на run()
    content = re.sub(pattern, 'run()', content)
    # Удаляем дублирующиеся вызовы run() если они есть
    content = re.sub(r'^run\(\)\s*$', '', content, flags=re.MULTILINE)
    # Добавляем run() в конце
    content = content.rstrip() + '\n\nrun()\n'
else:
    # Если условия нет, просто добавляем в конец
    content = content.rstrip() + '\n\nrun()\n'

with open(filename, 'w') as f:
    f.write(content)

print("✅ main_window.py исправлен")
