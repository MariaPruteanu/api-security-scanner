import requests
import json

# НОВЫЙ URL для версии 3 (работает без ключа)
BASE_URL = "https://petstore3.swagger.io/api/v3"

def get_pets_by_status(status="available"):
    url = f"{BASE_URL}/pet/findByStatus"
    params = {"status": status}
    headers = {"Accept": "application/json"}
    
    print(f"🔍 Запрос: GET {url}?status={status}")
    response = requests.get(url, params=params, headers=headers)
    
    print(f"📊 HTTP статус: {response.status_code}")
    
    if response.status_code == 200:
        try:
            return response.json()
        except:
            return {"error": "Невалидный JSON", "raw": response.text[:200]}
    else:
        return {"error": f"HTTP {response.status_code}", "raw": response.text[:200]}

if __name__ == "__main__":
    result = get_pets_by_status()
    print("✅ Итоговый результат:")
    print(json.dumps(result, indent=2, ensure_ascii=False))
