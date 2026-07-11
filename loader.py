import os
import json
import yaml
import requests
from urllib.parse import urlparse

def load_specification(source):
    """Загружает спецификацию из URL или файла, определяет формат и конвертирует в OpenAPI 3.1."""
    parsed = urlparse(source)
    if parsed.scheme in ('http', 'https'):
        response = requests.get(source)
        response.raise_for_status()
        content = response.text
    else:
        if not os.path.exists(source):
            raise FileNotFoundError(f"Файл не найден: {source}")
        with open(source, 'r', encoding='utf-8') as f:
            content = f.read()

    try:
        spec = json.loads(content)
    except json.JSONDecodeError:
        spec = yaml.safe_load(content)

    fmt = detect_format(spec)
    if fmt == 'swagger2':
        spec = convert_swagger2_to_openapi3(spec)
    elif fmt == 'postman':
        spec = convert_postman_to_openapi3(spec)
    # если openapi3 – оставляем как есть
    return spec

def detect_format(spec):
    if 'openapi' in spec and spec['openapi'].startswith('3.'):
        return 'openapi3'
    if 'swagger' in spec and spec['swagger'] == '2.0':
        return 'swagger2'
    if 'info' in spec and 'postman' in spec.get('info', {}).get('schema', ''):
        return 'postman'
    # можно также проверить наличие 'collection' в корне
    if 'collection' in spec and 'item' in spec.get('collection', {}):
        return 'postman'
    return 'openapi3'  # по умолчанию считаем OpenAPI

def convert_swagger2_to_openapi3(swagger):
    """Упрощённая конвертация Swagger 2.0 → OpenAPI 3.1."""
    openapi = {
        'openapi': '3.1.0',
        'info': swagger.get('info', {}),
        'servers': swagger.get('host', [])  # упрощённо
    }
    # Базовые пути
    paths = {}
    base_path = swagger.get('basePath', '')
    for path, path_item in swagger.get('paths', {}).items():
        full_path = base_path + path
        paths[full_path] = {}
        for method, operation in path_item.items():
            if method.lower() not in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
                continue
            paths[full_path][method.lower()] = {
                'summary': operation.get('summary', ''),
                'description': operation.get('description', ''),
                'parameters': convert_parameters(operation.get('parameters', [])),
                'responses': convert_responses(operation.get('responses', {}))
            }
    openapi['paths'] = paths
    # Компоненты – схемы (упрощённо)
    if 'definitions' in swagger:
        openapi['components'] = {'schemas': swagger['definitions']}
    return openapi

def convert_parameters(params):
    """Конвертирует параметры Swagger 2.0 в OpenAPI 3.1."""
    new_params = []
    for p in params:
        new_p = {
            'name': p.get('name'),
            'in': p.get('in'),
            'description': p.get('description', ''),
            'required': p.get('required', False),
            'schema': p.get('schema', {})
        }
        # Для query-параметров может быть type
        if 'type' in p and 'schema' not in p:
            new_p['schema'] = {'type': p['type']}
        new_params.append(new_p)
    return new_params

def convert_responses(responses):
    """Конвертирует responses Swagger 2.0 → OpenAPI 3.1."""
    new_resp = {}
    for code, resp in responses.items():
        new_resp[code] = {
            'description': resp.get('description', ''),
            'content': {}
        }
        if 'schema' in resp:
            new_resp[code]['content']['application/json'] = {'schema': resp['schema']}
    return new_resp

def convert_postman_to_openapi3(postman):
    """Упрощённая конвертация Postman Collection → OpenAPI 3.1."""
    openapi = {
        'openapi': '3.1.0',
        'info': {
            'title': postman.get('info', {}).get('name', 'Postman Collection'),
            'version': postman.get('info', {}).get('version', '1.0.0')
        },
        'paths': {}
    }
    items = postman.get('collection', {}).get('item', [])
    for item in items:
        # Если есть вложенные папки (item.item), обрабатываем рекурсивно
        if 'item' in item:
            # Для простоты пропускаем вложенные
            continue
        if 'request' not in item:
            continue
        request = item['request']
        method = request.get('method', 'get').lower()
        url = request.get('url', {})
        if isinstance(url, str):
            path = url
        else:
            path = url.get('raw', '')
            # также можно собрать из host + path
        if not path:
            continue
        # Убираем базовый URL, оставляем только путь
        # Здесь можно упрощённо взять path как есть
        openapi['paths'][path] = {
            method: {
                'summary': item.get('name', ''),
                'description': '',
                'parameters': [],
                'responses': {}
            }
        }
    return openapi
