with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Неправильный блок с ломаными отступами
old_block = """                resources_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                orig_dir = os.getcwd()
                os.chdir(resources_dir)

                try:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    scanner = APIScanner(base_url=self.target, timeout=self.timeout, scan_type=self.scan_type)
        self.log("⏳ Выполняется сканирование...")
                    raw_results = loop.run_until_complete(scanner.run_scan())
        self.log(f"✅ Сканирование завершено. Сырых результатов: {len(raw_results)}")
                except Exception as e:
                    self.log(f"❌ Ошибка при выполнении сканирования: {e}")
                    self.error.emit(f"Ошибка сканирования: {e}")"""

# Правильный блок с ровными отступами
new_block = """                resources_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                orig_dir = os.getcwd()
                os.chdir(resources_dir)

                try:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    scanner = APIScanner(base_url=self.target, timeout=self.timeout, scan_type=self.scan_type)
                    self.log("⏳ Выполняется сканирование...")
                    raw_results = loop.run_until_complete(scanner.run_scan())
                    self.log(f"✅ Сканирование завершено. Сырых результатов: {len(raw_results)}")
                except Exception as e:
                    self.log(f"❌ Ошибка при выполнении сканирования: {e}")
                    self.error.emit(f"Ошибка сканирования: {e}")
                finally:
                    os.chdir(orig_dir)"""

if old_block in content:
    content = content.replace(old_block, new_block)
    with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("✅ Отступы в блоке сканирования успешно исправлены!")
else:
    print("⚠️ Блок не найден. Возможно, он уже был изменён.")
