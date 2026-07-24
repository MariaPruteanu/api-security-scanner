#!/bin/bash
# build_dmg.sh — создание DMG для APIScannerPro

APP_NAME="APIScannerPro"
APP_PATH="dist/${APP_NAME}.app"
DMG_NAME="${APP_NAME}.dmg"
VOLUME_NAME="APIScannerPro"
BACKGROUND_IMG="resources/background_dmg.png"  # опционально
ICON_FILE="resources/app.icns"                 # опционально

# Проверка наличия приложения
if [ ! -d "$APP_PATH" ]; then
    echo "❌ Приложение не найдено: $APP_PATH"
    echo "Сначала соберите приложение командой: pyinstaller APIScannerPro.spec"
    exit 1
fi

# Установка create-dmg, если не установлен
if ! command -v create-dmg &> /dev/null; then
    echo "📦 Устанавливаем create-dmg..."
    brew install create-dmg
fi

# Создание временной папки
TMP_DIR=$(mktemp -d)

# Копируем приложение во временную папку
cp -R "$APP_PATH" "$TMP_DIR/"

# Создаём DMG
create-dmg \
    --volname "$VOLUME_NAME" \
    --volicon "$ICON_FILE" \
    --background "$BACKGROUND_IMG" \
    --window-pos 200 120 \
    --window-size 800 400 \
    --icon-size 100 \
    --icon "${APP_NAME}.app" 200 190 \
    --hide-extension "${APP_NAME}.app" \
    --app-drop-link 600 185 \
    "$DMG_NAME" \
    "$TMP_DIR/"

# Очистка
rm -rf "$TMP_DIR"

echo "✅ DMG создан: $DMG_NAME"
