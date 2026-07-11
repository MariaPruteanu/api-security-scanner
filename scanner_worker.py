import asyncio

async def run_scan(target, scan_type='basic'):
    """Заглушка, возвращающая разные результаты в зависимости от типа сканирования."""
    # Общие уязвимости для всех типов
    base_findings = [
        {"id": "1", "severity": "HIGH", "description": f"Уязвимость в {target}"},
        {"id": "2", "severity": "MEDIUM", "description": "Отсутствует HSTS"},
        {"id": "3", "severity": "LOW", "description": "Доступен отладочный эндпоинт"},
    ]
    
    # Дополнительные уязвимости для Premium
    premium_findings = [
        {"id": "4", "severity": "HIGH", "description": "SQL-инъекция в параметре id"},
        {"id": "5", "severity": "MEDIUM", "description": "Недостаточное логирование"},
    ]
    
    # Дополнительные уязвимости для Enterprise
    enterprise_findings = [
        {"id": "6", "severity": "CRITICAL", "description": "SSRF в эндпоинте /fetch"},
        {"id": "7", "severity": "HIGH", "description": "Mass Assignment в /users"},
        {"id": "8", "severity": "MEDIUM", "description": "Отсутствие rate limiting"},
    ]
    
    # Формируем результат в зависимости от типа
    if scan_type == 'basic':
        return base_findings
    elif scan_type == 'premium':
        return base_findings + premium_findings
    elif scan_type == 'enterprise':
        return base_findings + premium_findings + enterprise_findings
    else:
        return base_findings
