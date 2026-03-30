datas=[
    ('scanner', 'scanner'),
    ('rules', 'rules'),
    ('templates', 'templates'),
    ('output', 'output'),
    ('main.py', '.'),
    ('desktop_app.py', '.'),  # ← Добавьте desktop app
    ('requirements.txt', '.'),
    ('users.db', '.'),
],

hiddenimports=[
    'fastapi',
    'uvicorn',
    'httpx',
    'pydantic',
    'jwt',
    'sqlite3',
    'jinja2',
    'yaml',
    'asyncio',
    'webview',  # ← Добавьте pywebview
    'threading',
],
