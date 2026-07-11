#!/bin/bash
cd /Users/lenovo1/Desktop/api-security-scanner

# 1. Создаём файл license.txt с тестовыми ключами
cat > license.txt << 'EOF'
API_KEY=test-key-123
PREMIUM_KEY=PREMIUM-123
ENTERPRISE_KEY=ENTERPRISE-456
EOF
echo "✅ license.txt создан"

# 2. Исправляем относительные импорты на абсолютные
sed -i '' 's/from \.settings import/from desktop_app.settings import/g' desktop_app/main_window.py
sed -i '' 's/from \.database import/from desktop_app.database import/g' desktop_app/main_window.py
sed -i '' 's/from \.export import/from desktop_app.export import/g' desktop_app/main_window.py
echo "✅ Импорты исправлены"

# 3. Добавляем код для чтения license.txt в __init__ (вставляем после self.settings = load_settings())
# Ищем строку "self.settings = load_settings()" и вставляем после неё наш код
sed -i '' '/self.settings = load_settings()/a\
        # Загрузка ключей из license.txt\
        license_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "license.txt")\
        if not os.path.exists(license_path) and getattr(sys, "frozen", False):\
            license_path = os.path.join(os.path.dirname(sys.executable), "license.txt")\
        if os.path.exists(license_path):\
            try:\
                with open(license_path, "r", encoding="utf-8") as f:\
                    for line in f:\
                        if "=" in line:\
                            key, value = line.strip().split("=", 1)\
                            if key == "API_KEY":\
                                self.api_key = value\
                                self.settings["api_key"] = value\
                            elif key == "PREMIUM_KEY":\
                                self.license_valid["premium"] = True\
                                self.settings["premium_key"] = value\
                            elif key == "ENTERPRISE_KEY":\
                                self.license_valid["enterprise"] = True\
                                self.settings["enterprise_key"] = value\
                save_settings(self.settings)\
            except Exception as e:\
                print(f"Не удалось прочитать license.txt: {e}")
' desktop_app/main_window.py
echo "✅ Код для чтения license.txt добавлен"

# 4. Скрываем поле ввода API-ключа (делаем его неактивным)
sed -i '' 's/self.api_key_input.setPlaceholderText("🔑 API Key")/self.api_key_input.setPlaceholderText("🔑 Автоматическая загрузка")\n        self.api_key_input.setEnabled(False)/g' desktop_app/main_window.py
echo "✅ Поле ввода API-ключа скрыто"

# 5. Удаляем старые сборки
rm -rf dist/APIScanner.app build

# 6. Собираем приложение
pyinstaller --windowed --name "APIScanner" \
  --add-data "scanner:scanner" \
  --add-data "rules:rules" \
  --add-data "desktop_app:desktop_app" \
  --add-data "app_icon.icns:." \
  --icon app_icon.icns \
  desktop_app/main_window.py
echo "✅ Сборка завершена"

# 7. Копируем license.txt в папку dist (рядом с .app)
cp license.txt dist/

# 8. Снимаем квотирование и подписываем
xattr -d com.apple.quarantine dist/APIScanner.app 2>/dev/null || true
codesign --deep --force --sign - dist/APIScanner.app

# 9. Запускаем приложение
echo "✅ Готово! Запускаем APIScanner..."
dist/APIScanner.app/Contents/MacOS/APIScanner
