import os

APP_DIR = os.path.dirname(os.path.abspath(__file__))
LICENSE_FILE_NAME = "license.key"
USER_LICENSE_PATH = os.path.expanduser("~/Library/Application Support/APIScannerPro/license.key")

VALID_KEYS = {
    "premium": ["PREMIUM_KEY_123", "TEST_PREMIUM_456"],
    "enterprise": ["ENTERPRISE_KEY_789", "TEST_ENTERPRISE_000"]
}

def find_license_file():
    local_path = os.path.join(APP_DIR, LICENSE_FILE_NAME)
    if os.path.exists(local_path):
        return local_path
    if os.path.exists(USER_LICENSE_PATH):
        return USER_LICENSE_PATH
    return None

def load_license():
    license_file = find_license_file()
    if not license_file:
        return "free", "Бесплатный"
    try:
        with open(license_file, 'r') as f:
            key = f.read().strip()
    except:
        return "free", "Бесплатный"
    if key in VALID_KEYS["premium"]:
        return "premium", "Премиум (Платный)"
    elif key in VALID_KEYS["enterprise"]:
        return "enterprise", "Корпоративный"
    else:
        return "free", "Бесплатный"
