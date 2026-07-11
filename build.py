import PyInstaller.__main__
import os
import platform
import sys

def build():
    # Определяем целевую платформу
    system = platform.system()
    args = [
        'main_window.py',
        '--name=APIScannerPro',
        '--onefile',
        '--windowed',
        '--add-data=scanner:scanner',
        '--add-data=rules:rules',
        '--add-data=i18n.py:.',
        '--add-data=loader.py:.',
        '--add-data=key_loader.py:.',
        '--add-data=key_integration.py:.',
        '--add-data=advanced_report.py:.',
        '--add-data=charts.py:.',
        '--add-data=config:config',
        '--hidden-import=reportlab',
        '--hidden-import=matplotlib',
        '--hidden-import=jinja2',
        '--hidden-import=PyQt5',
        '--collect-all=reportlab',
        '--collect-all=matplotlib',
    ]
    if system == 'Darwin':
        args.append('--icon=app_icon.icns')
    elif system == 'Windows':
        args.append('--icon=app_icon.ico')
    else:
        # Linux — используем .png или иконку по умолчанию
        if os.path.exists('app_icon.png'):
            args.append('--icon=app_icon.png')
    PyInstaller.__main__.run(args)

if __name__ == '__main__':
    build()
