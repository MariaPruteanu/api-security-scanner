import re

with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Идеально правильный метод run с верными отступами
clean_run_method = """    def run(self):
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

            resources_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            orig_dir = os.getcwd()
            os.chdir(resources_dir)

            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                scanner = APIScanner(base_url=self.target, timeout=self.timeout, scan_type=self.scan_type)
                self.log("⏳ Выполняется сканирование...")
                raw_results = loop.run_until_complete(scanner.run_scan())
                self.log(f"✅ Сканирование завершено. Сырых результатов: {len(raw_results)}")
                self.finished.emit(raw_results)
            except Exception as e:
                self.log(f"❌ Ошибка при выполнении сканирования: {e}")
                self.error.emit(f"Ошибка сканирования: {e}")
            finally:
                os.chdir(orig_dir)
                
        except Exception as e:
            self.log(f"❌ Критическая ошибка в run(): {e}")
            self.error.emit(f"Критическая ошибка: {e}")

"""

# Находим def run(self): и заменяем всё до следующего def или class
pattern = r'(    def run\(self\):.*?)(?=\n    def |\n    @|\nclass |\Z)'

match = re.search(pattern, content, re.DOTALL)
if match:
    content = content[:match.start()] + clean_run_method + content[match.end():]
    with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("✅ Метод run() полностью переписан и выровнен!")
else:
    print("⚠️ Не удалось найти метод run(). Проверь файл вручную.")
