import PyInstaller.__main__
import os
import platform

def build():
    args = [
        'main_window.py',  # точка входа
        '--name=APIScannerPro',
        '--onefile',
        '--windowed',
        '--add-data=scanner:scanner',
        '--add-data=rules:rules',
        '--add-data=i18n.py:.',
        '--add-data=loader.py:.',
        '--add-data=advanced_report.py:.',
        '--add-data=charts.py:.',
        '--add-data=DejaVuSans.ttf:.',
        '--hidden-import=reportlab',
        '--hidden-import=matplotlib',
        '--hidden-import=jinja2',
        '--hidden-import=PyQt5',
        '--collect-all=reportlab',
        '--collect-all=matplotlib',
    ]
    # Для macOS добавляем иконку
    if platform.system() == 'Darwin':
        args.append('--icon=app_icon.icns')
    elif platform.system() == 'Windows':
        args.append('--icon=app_icon.ico')
    PyInstaller.__main__.run(args)

if __name__ == '__main__':
    build()
