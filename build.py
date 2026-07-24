import PyInstaller.__main__
import os
import platform

def build():
    system = platform.system()
    args = [
        'main_window.py',
        '--name=APIScannerPro',
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
        '--add-data=version.py:.',
        '--add-data=update_checker.py:.',
        '--add-data=usage_tracker.py:.',
        '--add-data=desktop_usage.py:.',
        '--add-data=stripe_payment.py:.',
        '--add-data=web:web',
        '--add-data=USER_GUIDE.txt:.',
<<<<<<< HEAD
        '--add-data=/Users/lenovo1/Library/Python/3.9/lib/python/site-packages/PyQt5/Qt5/plugins:PyQt5/Qt5/plugins',
=======
        import PyQt5
import os
pyqt5_plugins = os.path.join(os.path.dirname(PyQt5.__file__), 'Qt5', 'plugins')
f'--add-data={pyqt5_plugins}:PyQt5/Qt5/plugins' ,
>>>>>>> 05db96294ade776bf04401527428846dc52b3428
        '--hidden-import=reportlab',
        '--hidden-import=matplotlib',
        '--hidden-import=jinja2',
        '--hidden-import=PyQt5',
        '--hidden-import=stripe',
        '--hidden-import=desktop_app.settings',
        '--hidden-import=key_integration',
        '--collect-all=reportlab',
        '--collect-all=matplotlib',
        '--osx-bundle-identifier=com.yourcompany.apiscannerpro',
    ]
    if system == 'Darwin':
        args.append('--icon=app_icon.icns')
    elif system == 'Windows':
        args.append('--icon=app_icon.ico')
    else:
        if os.path.exists('app_icon.png'):
            args.append('--icon=app_icon.png')
    PyInstaller.__main__.run(args)

if __name__ == '__main__':
    build()
