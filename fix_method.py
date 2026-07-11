with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Код нового метода
new_method = """    def show_extra_options(self):
        \"\"\"Показать дополнительные опции сканирования\"\"\"
        dlg = QDialog(self)
        dlg.setWindowTitle("Дополнительные опции")
        dlg.setMinimumWidth(350)
        layout = QFormLayout(dlg)
        
        # Таймаут
        timeout_spin = QSpinBox()
        timeout_spin.setRange(5, 120)
        timeout_spin.setValue(self.settings.get('timeout', 30))
        timeout_spin.setSuffix(" сек")
        layout.addRow("Таймаут запросов:", timeout_spin)
        
        # Кнопки OK/Cancel
        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.accepted.connect(dlg.accept)
        btn_box.rejected.connect(dlg.reject)
        layout.addRow(btn_box)
        
        if dlg.exec_() == QDialog.Accepted:
            self.settings['timeout'] = timeout_spin.value()
            save_settings(self.settings)
            QMessageBox.information(self, "Опции", "✅ Дополнительные опции сохранены!")

"""

new_lines = []
for line in lines:
    # Вставляем перед методом browse_file
    if line.strip().startswith('def browse_file(self):'):
        new_lines.append(new_method)
    new_lines.append(line)

with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
    f.write(''.join(new_lines))

print("✅ Метод show_extra_options успешно добавлен!")
