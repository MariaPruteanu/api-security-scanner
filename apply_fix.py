with open('desktop_app/main_window.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_code = '''    def apply_theme(self):
        theme = self.settings.get('theme', 'dark')
        if theme == 'dark':
            style = DARK_STYLE
        else:
            style = LIGHT_STYLE
        self.setStyleSheet(style)
        # Принудительно обновляем все дочерние виджеты
        for widget in self.findChildren(QWidget):
            widget.setStyleSheet(style)
        self.update()
        self.repaint()'''

new_code = '''    def apply_theme(self):
        theme = self.settings.get('theme', 'dark')
        app = QApplication.instance()
        
        if theme == 'dark':
            style = DARK_STYLE
        else:
            style = LIGHT_STYLE
        
        # Применяем стиль ко ВСЕМУ приложению
        app.setStyleSheet(style)
        
        # Принудительно обновляем все виджеты
        for widget in app.allWidgets():
            widget.style().unpolish(widget)
            widget.style().polish(widget)
        
        self.update()
        self.repaint()'''

content = content.replace(old_code, new_code)

with open('desktop_app/main_window.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("✅ Готово! Перезапусти приложение.")
