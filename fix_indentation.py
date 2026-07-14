with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Находим проблемный блок и заменяем его на правильный
old_code = """    def run(self):
        try:
            if self.mode == 'local':
                self.log("🔍 Запуск локального сканирования...")
        self.log(f"🎯 Цель: {self.target}")

                try:
                    APIScanner = self._load_scanner()
        self.log("✅ Модуль scanner.core загружен")
                except Exception as e:
                    self.log(f"❌ Ошибка загрузки сканера: {e}")
                    self.error.emit(f"Ошибка загрузки сканера: {e}")
                    return"""

new_code = """    def run(self):
        try:
            if self.mode == 'local':
                self.log("🔍 Запуск локального сканирования...")
            
            self.log(f"🎯 Цель: {self.target}")

            try:
                APIScanner = self._load_scanner()
                self.log("✅ Модуль scanner.core загружен")
            except Exception as e:
                self.log(f"❌ Ошибка загрузки сканера: {e}")
                self.error.emit(f"Ошибка загрузки сканера: {e}")
                return
        except Exception as e:
            self.log(f"❌ Ошибка в run(): {e}")
            self.error.emit(f"Ошибка: {e}")
            return"""

if old_code in content:
    content = content.replace(old_code, new_code)
    with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("✅ Отступы исправлены!")
else:
    print("⚠️ Не удалось найти проблемный блок. Проверь код вручную.")
