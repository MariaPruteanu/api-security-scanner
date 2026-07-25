import sys
import re

filename = "main_window.py"
with open(filename, 'r') as f:
    lines = f.readlines()

# Удаляем все старые методы оплаты
new_lines = []
i = 0
while i < len(lines):
    line = lines[i]
    if 'def buy_pro' in line or 'def _defi_payment_dialog' in line or 'def _check_payment' in line:
        # Пропускаем всю функцию
        i += 1
        # Считаем отступ для определения конца функции
        indent = len(line) - len(line.lstrip())
        while i < len(lines):
            current_indent = len(lines[i]) - len(lines[i].lstrip())
            # Если отступ меньше или равен indent - значит функция закончилась
            if current_indent <= indent and lines[i].strip():
                break
            i += 1
        continue
    else:
        new_lines.append(line)
        i += 1

# Находим строку def run()
run_index = None
for i, line in enumerate(new_lines):
    if line.strip().startswith('def run()'):
        run_index = i
        break

if run_index is None:
    print("❌ Не найдена def run()")
    sys.exit(1)

# Определяем отступ для методов (4 пробела)
indent = '    '

methods = [
    '',
    f'{indent}def buy_pro(self):',
    f'{indent}    """Открывает диалог с вариантами оплаты."""',
    f'{indent}    msg = """',
    f'{indent}Выберите способ оплаты:',
    '',
    f'{indent}1️⃣ DeFi (USDT/Solana) — для международных платежей',
    f'{indent}2️⃣ Сайт — для оплаты картой (РФ и зарубеж)',
    f'{indent}"""',
    f'{indent}    reply = QMessageBox.question(',
    f'{indent}        self, "Выберите способ оплаты",',
    f'{indent}        msg,',
    f'{indent}        QMessageBox.Yes | QMessageBox.No,',
    f'{indent}        QMessageBox.Yes',
    f'{indent}    )',
    f'{indent}    if reply == QMessageBox.Yes:',
    f'{indent}        self._defi_payment_dialog()',
    f'{indent}    else:',
    f'{indent}        import webbrowser',
    f'{indent}        webbrowser.open("https://your-site.com/checkout")',
    '',
    f'{indent}def _defi_payment_dialog(self):',
    f'{indent}    """Показывает окно с информацией для оплаты через DeFi."""',
    f'{indent}    try:',
    f'{indent}        import requests',
    f'{indent}        resp = requests.get(f"{{self.api_url}}/api/payment/defi/info", timeout=30)',
    f'{indent}        if resp.status_code != 200:',
    f'{indent}            QMessageBox.warning(self, "Ошибка", "Не удалось получить информацию для оплаты.")',
    f'{indent}            return',
    f'{indent}        data = resp.json()',
    f'{indent}        msg = f"""',
    f'{indent}Оплатите {{data["amount"]}} {{data["token"]}} на кошелёк:',
    '',
    f'{indent}🌐 Сеть: {{data["network"]}}',
    f'{indent}💰 Адрес: {{data["wallet"]}}',
    f'{indent}📝 Memo: {{data["memo"]}}',
    '',
    f'{indent}После оплаты нажмите «Проверить оплату».',
    f'{indent}"""',
    f'{indent}        reply = QMessageBox.question(',
    f'{indent}            self, "Оплата через DeFi",',
    f'{indent}            msg,',
    f'{indent}            QMessageBox.Yes | QMessageBox.No,',
    f'{indent}            QMessageBox.Yes',
    f'{indent}        )',
    f'{indent}        if reply == QMessageBox.Yes:',
    f'{indent}            from PyQt5.QtWidgets import QApplication',
    f'{indent}            clipboard = QApplication.clipboard()',
    f'{indent}            clipboard.setText(data["wallet"])',
    f'{indent}            QMessageBox.information(self, "Адрес скопирован", "Адрес кошелька скопирован в буфер обмена.")',
    f'{indent}            self._check_payment()',
    f'{indent}    except Exception as e:',
    f'{indent}        QMessageBox.critical(self, "Ошибка", f"Ошибка: {{e}}")',
    '',
    f'{indent}def _check_payment(self):',
    f'{indent}    """Проверяет, была ли оплата."""',
    f'{indent}    try:',
    f'{indent}        import requests',
    f'{indent}        resp = requests.post(f"{{self.api_url}}/api/payment/defi/check", timeout=30)',
    f'{indent}        if resp.status_code == 200:',
    f'{indent}            data = resp.json()',
    f'{indent}            if data.get("success"):',
    f'{indent}                self.license_valid["premium"] = True',
    f'{indent}                self.settings["premium_key"] = "PAID-VIA-DEFI"',
    f'{indent}                save_settings(self.settings)',
    f'{indent}                self.update_usage_status()',
    f'{indent}                QMessageBox.information(self, "Успех!", data.get("message", "Лицензия активирована!"))',
    f'{indent}            else:',
    f'{indent}                QMessageBox.warning(self, "Оплата не найдена", data.get("message", "Попробуйте ещё раз через минуту."))',
    f'{indent}        else:',
    f'{indent}            QMessageBox.warning(self, "Ошибка", "Не удалось проверить оплату.")',
    f'{indent}    except Exception as e:',
    f'{indent}        QMessageBox.critical(self, "Ошибка", f"Ошибка проверки: {{e}}")',
]

# Вставляем методы перед def run()
new_lines = new_lines[:run_index] + methods + new_lines[run_index:]

with open(filename, 'w') as f:
    f.write('\n'.join(new_lines))

print("✅ Методы оплаты добавлены с правильными отступами")
