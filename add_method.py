with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Находим место для вставки (после on_mode_changed)
old_code = '''    def on_mode_changed(self, mode):
        if mode == 'cloud':
            self.api_key_input.setVisible(True)
            if self.api_key:
                self.api_key_input.setText(self.api_key)
        else:
            self.api_key_input.setVisible(False)'''

new_code = '''    def on_mode_changed(self, mode):
        if mode == 'cloud':
            self.api_key_input.setVisible(True)
            if self.api_key:
                self.api_key_input.setText(self.api_key)
        else:
            self.api_key_input.setVisible(False)

    def show_extra_options(self):
        """Показать дополнительные опции сканирования"""
        dlg = QDialog(self)
        dlg.setWindowTitle("Дополнительные опции")
        dlg.setMinimumWidth(400)
        
        layout = QFormLayout(dlg)
        
        # Таймаут запросов
        timeout_spin = QSpinBox()
        timeout_spin.setRange(5, 120)
        timeout_spin.setValue(self.settings.get('timeout', 30))
        timeout_spin.setSuffix(" сек")
        layout.addRow("Таймаут запросов:", timeout_spin)
        
        # Количество потоков
        threads_spin = QSpinBox()
        threads_spin.setRange(1, 20)
        threads_spin.setValue(self.settings.get('threads', 5))
        layout.addRow("Количество потоков:", threads_spin)
        
        # Задержка между запросами
        delay_spin = QSpinBox()
        delay_spin.setRange(0, 5000)
        delay_spin.setValue(self.settings.get('delay', 100))
        delay_spin.setSuffix(" мс")
        layout.addRow("Задержка между запросами:", delay_spin)
        
        # Проверять только GET
        get_only_cb = QCheckBox()
        get_only_cb.setChecked(self.settings.get('get_only', False))
        layout.addRow("Только GET запросы:", get_only_cb)
        
        # Кнопки OK/Cancel
        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.accepted.connect(dlg.accept)
        btn_box.rejected.connect(dlg.reject)
        layout.addRow(btn_box)
        
        if dlg.exec_() == QDialog.Accepted:
            self.settings['timeout'] = timeout_spin.value()
            self.settings['threads'] = threads_spin.value()
            self.settings['delay'] = delay_spin.value()
            self.settings['get_only'] = get_only_cb.isChecked()
            save_settings(self.settings)
            QMessageBox.information(self, "Опции", "✅ Дополнительные опции сохранены!")'''

content = content.replace(old_code, new_code)

with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("✅ Метод show_extra_options добавлен!")
