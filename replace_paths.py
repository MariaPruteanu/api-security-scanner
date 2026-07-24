import re
import sys
import os

filename = "main_window.py"
with open(filename, 'r') as f:
    content = f.read()

# 1. Заменяем os.path.join(base_dir, "scanner", "core.py") на resource_path("scanner/core.py")
content = re.sub(
    r'os\.path\.join\(base_dir,\s*["\']scanner["\'],\s*["\']core\.py["\']\)',
    'resource_path("scanner/core.py")',
    content
)

# 2. Заменяем os.path.join(base_dir, "rules") на resource_path("rules")
content = re.sub(
    r'os\.path\.join\(base_dir,\s*["\']rules["\']\)',
    'resource_path("rules")',
    content
)

# 3. Заменяем os.path.join(base_dir, "config") на resource_path("config")
content = re.sub(
    r'os\.path\.join\(base_dir,\s*["\']config["\']\)',
    'resource_path("config")',
    content
)

# 4. Заменяем любые другие осмысленные пути (i18n.py, loader.py и т.д.)
# Поскольку они обычно используются через импорт, дополнительных замен не требуется.

with open(filename, 'w') as f:
    f.write(content)

print("✅ Все пути заменены на resource_path()")
