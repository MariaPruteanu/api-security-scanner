import sys
import os
import json
import yaml

def load_spec_file(filepath):
    """Загружает спецификацию из файла и возвращает словарь."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return yaml.safe_load(content)
    except Exception as e:
        return None, f"❌ Ошибка чтения файла: {e}"

def validate_spec(spec_dict):
    """
    Проверяет спецификацию на соответствие OpenAPI 3.x или Swagger 2.0.
    Возвращает (is_valid, message).
    """
    if not spec_dict:
        return False, "❌ Спецификация пуста или не загружена"

    # Определяем версию
    if 'openapi' in spec_dict:
        version = spec_dict['openapi']
        if version.startswith('3.'):
            return validate_openapi3(spec_dict)
        else:
            return False, f"❌ Неподдерживаемая версия OpenAPI: {version}"
    elif 'swagger' in spec_dict and spec_dict['swagger'] == '2.0':
        return validate_swagger2(spec_dict)
    else:
        return False, "❌ Не удалось определить формат спецификации (не OpenAPI 3.x и не Swagger 2.0)"

def validate_openapi3(spec_dict):
    """Валидация OpenAPI 3.x."""
    try:
        from openapi_spec_validator import validate_spec as validate_openapi
        validate_openapi(spec_dict)
        return True, "✅ Спецификация OpenAPI 3.x валидна"
    except ImportError:
        return False, "❌ Библиотека openapi-spec-validator не установлена. Установите: pip install openapi-spec-validator"
    except Exception as e:
        return False, f"❌ Ошибка валидации OpenAPI 3.x: {e}"

def validate_swagger2(spec_dict):
    """Валидация Swagger 2.0."""
    try:
        from openapi_spec_validator import validate_spec as validate_openapi
        # Swagger 2.0 тоже валидируется этой библиотекой
        validate_openapi(spec_dict)
        return True, "✅ Спецификация Swagger 2.0 валидна"
    except ImportError:
        return False, "❌ Библиотека openapi-spec-validator не установлена. Установите: pip install openapi-spec-validator"
    except Exception as e:
        return False, f"❌ Ошибка валидации Swagger 2.0: {e}"
