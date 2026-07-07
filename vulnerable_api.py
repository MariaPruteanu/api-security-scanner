from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel
from typing import Optional
import sqlite3
import subprocess
import os

app = FastAPI(title="Vulnerable API for Testing", version="1.0")

# ========== БАЗА ДАННЫХ ==========
db = sqlite3.connect("vulnerable.db", check_same_thread=False)
db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT)")
db.execute("INSERT OR IGNORE INTO users VALUES (1, 'alice', 'password123', 'alice@test.com', 'user')")
db.execute("INSERT OR IGNORE INTO users VALUES (2, 'bob', 'qwerty', 'bob@test.com', 'user')")
db.execute("INSERT OR IGNORE INTO users VALUES (3, 'admin', 'admin123', 'admin@test.com', 'admin')")
db.commit()

# ========== МОДЕЛИ ==========
class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None
    isAdmin: Optional[bool] = None

# ========== УЯЗВИМЫЕ ЭНДПОИНТЫ ==========

# 1. BOLA/IDOR - Broken Object Level Authorization
@app.get("/users/{user_id}")
async def get_user(user_id: int):
    """Нет проверки прав доступа - любой может получить данные любого пользователя"""
    cursor = db.execute("SELECT id, username, email, password, role FROM users WHERE id=?", (user_id,))
    user = cursor.fetchone()
    if user:
        return {"id": user[0], "username": user[1], "email": user[2], "password": user[3], "role": user[4]}
    return {"error": "User not found"}

# 2. SQL Injection
@app.get("/search")
async def search_user(username: str):
    """Уязвимость к SQL-инъекциям"""
    query = f"SELECT * FROM users WHERE username='{username}'"  # УЯЗВИМОСТЬ!
    try:
        cursor = db.execute(query)
        users = cursor.fetchall()
        return {"users": [{"id": u[0], "username": u[1], "email": u[2]} for u in users]}
    except Exception as e:
        return {"error": str(e)}  # Раскрытие деталей ошибки

# 3. XSS - Reflected Cross-Site Scripting
@app.get("/greet")
async def greet(name: str):
    """Отражённый XSS - пользовательский ввод возвращается без экранирования"""
    return {"message": f"<h1>Hello, {name}!</h1>"}  # УЯЗВИМОСТЬ!

# 4. SSRF - Server-Side Request Forgery
@app.get("/fetch")
async def fetch_url(url: str):
    """SSRF - сервер делает запрос по указанному URL"""
    import httpx
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, timeout=5.0)
            return {"status": resp.status_code, "content": resp.text[:500]}
    except Exception as e:
        return {"error": str(e)}

# 5. Path Traversal
@app.get("/files")
async def get_file(filename: str):
    """Path Traversal - можно читать файлы за пределами директории"""
    try:
        filepath = f"./files/{filename}"  # УЯЗВИМОСТЬ!
        with open(filepath, "r") as f:
            return {"content": f.read()}
    except Exception as e:
        return {"error": str(e)}

# 6. Mass Assignment
@app.patch("/users/{user_id}")
async def update_user(user_id: int, data: UserUpdate):
    """Mass Assignment - можно изменить любые поля, включая role и isAdmin"""
    update_fields = []
    update_values = []
    
    for field, value in data.dict(exclude_unset=True).items():
        update_fields.append(f"{field}=?")
        update_values.append(value)
    
    if update_fields:
        query = f"UPDATE users SET {', '.join(update_fields)} WHERE id=?"
        update_values.append(user_id)
        db.execute(query, update_values)
        db.commit()
    
    cursor = db.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = cursor.fetchone()
    return {"id": user[0], "username": user[1], "email": user[2], "role": user[3]}

# 7. Excessive Data Exposure
@app.get("/users/{user_id}/profile")
async def get_user_profile(user_id: int):
    """Раскрытие лишних данных - возвращает password, internal_id и т.д."""
    cursor = db.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = cursor.fetchone()
    if user:
        return {
            "id": user[0],
            "username": user[1],
            "password": user[2],  # УЯЗВИМОСТЬ!
            "email": user[3],
            "role": user[4],
            "internal_id": f"INT-{user[0]}-SECRET",  # УЯЗВИМОСТЬ!
            "api_key": "sk-test-123456789"  # УЯЗВИМОСТЬ!
        }
    return {"error": "User not found"}

# 8. Broken Authentication - принимает любой токен
@app.get("/users/me")
async def get_current_user(request: Request):
    """Принимает любой токен без проверки"""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        # Нет проверки токена! Просто возвращаем данные
        return {"user": "test_user", "token": token, "role": "admin"}
    return {"error": "No token provided"}

# 9. Command Injection
@app.get("/ping")
async def ping_host(host: str):
    """Command Injection - выполнение системных команд"""
    try:
        result = subprocess.run(
            f"ping -c 1 {host}",  # УЯЗВИМОСТЬ!
            shell=True,
            capture_output=True,
            text=True,
            timeout=5
        )
        return {"output": result.stdout}
    except Exception as e:
        return {"error": str(e)}

# 10. Open Redirect
@app.get("/redirect")
async def redirect_url(url: str):
    """Open Redirect - редирект на любой URL"""
    return RedirectResponse(url=url)  # УЯЗВИМОСТЬ!

# 11. Verbose Error Messages
@app.post("/process")
async def process_data(request: Request):
    """Раскрытие деталей ошибок"""
    try:
        data = await request.json()
        result = 100 / data.get("value", 0)  # Деление на ноль
        return {"result": result}
    except Exception as e:
        return {
            "error": str(e),
            "traceback": "Full stack trace here...",  # УЯЗВИМОСТЬ!
            "debug_info": "Internal server details"
        }

# 12. Missing Rate Limiting
@app.post("/login")
async def login(username: str, password: str):
    """Нет защиты от brute force"""
    cursor = db.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    user = cursor.fetchone()
    if user:
        return {"status": "success", "token": "fake-jwt-token"}
    return {"status": "failed", "message": "Invalid credentials"}

# 13. Unsafe HTTP Methods (TRACE, PUT, DELETE разрешены)
@app.delete("/users/{user_id}")
async def delete_user(user_id: int):
    """Удаление пользователя без проверки прав"""
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    return {"status": "deleted"}

@app.put("/users/{user_id}")
async def replace_user(user_id: int, data: UserUpdate):
    """Полная замена пользователя"""
    return {"status": "replaced"}

# 14. GraphQL Introspection (если добавим GraphQL)
@app.post("/graphql")
async def graphql_endpoint(request: Request):
    """GraphQL с включенной introspection"""
    data = await request.json()
    query = data.get("query", "")
    
    if "__schema" in query:
        return {
            "data": {
                "__schema": {
                    "types": [
                        {"name": "Query"},
                        {"name": "User"},
                        {"name": "String"}
                    ]
                }
            }
        }
    
    return {"data": {"result": "mock"}}

# 15. Sensitive Data in URL
@app.get("/api/data")
async def get_data(api_key: str, token: str):
    """Чувствительные данные передаются через GET-параметры"""
    return {"status": "ok", "api_key": api_key, "token": token}

# 16. CORS Misconfiguration
@app.get("/cors-test")
async def cors_test(request: Request):
    """Слишком разрешительная CORS политика"""
    origin = request.headers.get("origin", "*")
    response = Response(content='{"status": "ok"}', media_type="application/json")
    response.headers["Access-Control-Allow-Origin"] = "*"  # УЯЗВИМОСТЬ!
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

# 17. Debug Mode Enabled
@app.get("/debug")
async def debug_info():
    """Раскрытие отладочной информации"""
    return {
        "debug": True,
        "version": "1.0.0-dev",
        "environment": "development",
        "secret_key": "super-secret-key-12345",
        "database": "sqlite:///vulnerable.db"
    }

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("🔓 Vulnerable API for Testing")
    print("🌐 http://127.0.0.1:8080")
    print("=" * 60)
    uvicorn.run(app, host="127.0.0.1", port=8080)
