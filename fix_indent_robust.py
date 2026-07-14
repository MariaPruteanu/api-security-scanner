with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
in_broken_block = False

for i, line in enumerate(lines):
    stripped = line.strip()
    
    # Если нашли начало сломанного блока
    if 'resources_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))' in stripped:
        in_broken_block = True
        new_lines.append('            resources_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))\n')
        continue
    
    if in_broken_block:
        if 'orig_dir = os.getcwd()' in stripped:
            new_lines.append('            orig_dir = os.getcwd()\n')
            continue
        if 'os.chdir(resources_dir)' in stripped:
            new_lines.append('            os.chdir(resources_dir)\n')
            continue
        if stripped == 'try:' and 'loop = asyncio.new_event_loop()' in lines[i+1]:
            new_lines.append('            try:\n')
            continue
        if 'loop = asyncio.new_event_loop()' in stripped:
            new_lines.append('                loop = asyncio.new_event_loop()\n')
            continue
        if 'asyncio.set_event_loop(loop)' in stripped:
            new_lines.append('                asyncio.set_event_loop(loop)\n')
            continue
        if 'scanner = APIScanner(base_url=self.target' in stripped:
            new_lines.append('                scanner = APIScanner(base_url=self.target, timeout=self.timeout, scan_type=self.scan_type)\n')
            continue
        if 'self.log("⏳ Выполняется сканирование...")' in stripped:
            new_lines.append('                self.log("⏳ Выполняется сканирование...")\n')
            continue
        if 'raw_results = loop.run_until_complete(scanner.run_scan())' in stripped:
            new_lines.append('                raw_results = loop.run_until_complete(scanner.run_scan())\n')
            continue
        if 'self.log(f"✅ Сканирование завершено. Сырых результатов: {len(raw_results)}")' in stripped:
            new_lines.append('                self.log(f"✅ Сканирование завершено. Сырых результатов: {len(raw_results)}")\n')
            continue
        if 'except Exception as e:' in stripped and 'Ошибка при выполнении сканирования' in lines[i+1]:
            new_lines.append('            except Exception as e:\n')
            continue
        if 'self.log(f"❌ Ошибка при выполнении сканирования: {e}")' in stripped:
            new_lines.append('                self.log(f"❌ Ошибка при выполнении сканирования: {e}")\n')
            continue
        if 'self.error.emit(f"Ошибка сканирования: {e}")' in stripped:
            new_lines.append('                self.error.emit(f"Ошибка сканирования: {e}")\n')
            new_lines.append('            finally:\n')
            new_lines.append('                os.chdir(orig_dir)\n')
            in_broken_block = False
            continue
            
    new_lines.append(line)

with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print("✅ Отступы принудительно исправлены!")
