# -*- coding: utf-8 -*-
"""
Интернационализация (i18n) для API Security Scanner
"""

LANGUAGE = 'ru'

TRANSLATIONS = {
    # Главное окно
    'app_title': {
        'ru': 'API Security Scanner Pro',
        'en': 'API Security Scanner Pro'
    },
    'menu_file': {
        'ru': '📁 Файл',
        'en': '📁 File'
    },
    'menu_export': {
        'ru': '📤 Экспорт отчёта',
        'en': '📤 Export report'
    },
    'menu_exit': {
        'ru': '✕ Выход',
        'en': '✕ Exit'
    },
    'menu_history': {
        'ru': '📜 История',
        'en': '📜 History'
    },
    'menu_show_history': {
        'ru': '📋 Показать историю',
        'en': '📋 Show history'
    },
    'menu_settings': {
        'ru': '⚙️ Настройки',
        'en': '⚙️ Settings'
    },
    'menu_options': {
        'ru': '🛠 Дополнительные опции',
        'en': '🛠 Advanced options'
    },
    'menu_help': {
        'ru': '❓ Помощь',
        'en': '❓ Help'
    },
    'menu_about': {
        'ru': 'ℹ️ О программе',
        'en': 'ℹ️ About'
    },
    'menu_help_errors': {
        'ru': '📖 Справка по ошибкам',
        'en': '📖 Error help'
    },
    'menu_rules_knowledge': {
        'ru': '📚 База знаний правил',
        'en': '📚 Rules knowledge base'
    },

    # Интерфейс
    'target_label': {
        'ru': '🎯 Цель:',
        'en': '🎯 Target:'
    },
    'browse_btn': {
        'ru': '📂 Обзор',
        'en': '📂 Browse'
    },
    'mode_label': {
        'ru': 'Режим:',
        'en': 'Mode:'
    },
    'mode_local': {
        'ru': '🖥️ Локальный',
        'en': '🖥️ Local'
    },
    'mode_cloud': {
        'ru': '☁️ Облачный',
        'en': '☁️ Cloud'
    },
    'type_label': {
        'ru': 'Тип:',
        'en': 'Type:'
    },
    'type_basic': {
        'ru': 'Базовый (Бесплатный)',
        'en': 'Basic (Free)'
    },
    'type_premium': {
        'ru': 'Премиум (Платный)',
        'en': 'Premium (Paid)'
    },
    'type_enterprise': {
        'ru': 'Корпоративный (Pro)',
        'en': 'Enterprise (Pro)'
    },
    'api_key_placeholder': {
        'ru': 'API Ключ',
        'en': 'API Key'
    },
    'start_scan_btn': {
        'ru': '🚀 Начать сканирование',
        'en': '🚀 Start Scan'
    },
    'stop_scan_btn': {
        'ru': '⏹ Остановить',
        'en': '⏹ Stop'
    },
    'report_btn': {
        'ru': '📊 Отчёт',
        'en': '📊 Report'
    },

    # Статусы
    'status_ready': {
        'ru': '✅ Готов к работе',
        'en': '✅ Ready'
    },
    'status_scanning': {
        'ru': '⏳ Сканирование в режиме {mode} ({type})...',
        'en': '⏳ Scanning in {mode} mode ({type})...'
    },
    'status_stopped': {
        'ru': '⏹ Сканирование остановлено пользователем',
        'en': '⏹ Scan stopped by user'
    },
    'status_error': {
        'ru': '❌ Ошибка',
        'en': '❌ Error'
    },
    'status_finished': {
        'ru': '✅ Найдено {count} уязвимостей.',
        'en': '✅ Found {count} vulnerabilities.'
    },

    # Прогресс
    'progress_ready': {
        'ru': '🔄 Готов к работе',
        'en': '🔄 Ready'
    },
    'progress_preparing': {
        'ru': '⏳ Подготовка...',
        'en': '⏳ Preparing...'
    },
    'progress_collecting': {
        'ru': '📡 Сбор данных...',
        'en': '📡 Collecting data...'
    },
    'progress_analyzing': {
        'ru': '🔍 Анализ уязвимостей...',
        'en': '🔍 Analyzing vulnerabilities...'
    },
    'progress_rules': {
        'ru': '⚙️ Проверка правил...',
        'en': '⚙️ Checking rules...'
    },
    'progress_report': {
        'ru': '📊 Формирование отчёта...',
        'en': '📊 Generating report...'
    },
    'progress_finishing': {
        'ru': '✅ Завершение...',
        'en': '✅ Finishing...'
    },
    'progress_stopped': {
        'ru': '⏹ Остановлено',
        'en': '⏹ Stopped'
    },
    'progress_error': {
        'ru': '❌ Ошибка',
        'en': '❌ Error'
    },

    # Таблица результатов
    'table_id': {
        'ru': 'ID',
        'en': 'ID'
    },
    'table_severity': {
        'ru': 'Уровень опасности',
        'en': 'Severity'
    },
    'table_description': {
        'ru': 'Описание',
        'en': 'Description'
    },
    'table_endpoint': {
        'ru': 'Эндпоинт',
        'en': 'Endpoint'
    },
    'table_recommendation': {
        'ru': 'Рекомендация',
        'en': 'Recommendation'
    },

    # Ошибки
    'error_no_target': {
        'ru': 'Пожалуйста, укажите URL или файл для сканирования.',
        'en': 'Please specify URL or file to scan.'
    },
    'error_no_api_key': {
        'ru': 'Для облачного режима введите ваш API-ключ.',
        'en': 'For cloud mode, enter your API key.'
    },
}

def set_language(lang):
    global LANGUAGE
    if lang in ('ru', 'en'):
        LANGUAGE = lang
    else:
        LANGUAGE = 'ru'

def tr(key):
    return TRANSLATIONS.get(key, {}).get(LANGUAGE, key)
