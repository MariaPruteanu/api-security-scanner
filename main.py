from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional, List
import jwt
import hashlib
import sqlite3
import uvicorn

# ========== КОНФИГУРАЦИЯ ==========
SECRET_KEY = "vkr-api-scanner-secret-key-2026-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

app = FastAPI(
    title="API Security Scanner v1.0",
    description="Инструмент автоматизированного анализа защищённости API (ВКР МИФИ 2026)",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== БАЗА ДАННЫХ ==========
DB_PATH = "users.db"
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS users 
             (id INTEGER PRIMARY KEY AUTOINCREMENT, 
              username TEXT UNIQUE, 
              password TEXT,
              email TEXT,
              created_at TEXT)''')

c.execute('''CREATE TABLE IF NOT EXISTS reports 
             (id INTEGER PRIMARY KEY AUTOINCREMENT, 
              user_id INTEGER, 
              target_url TEXT,
              openapi_url TEXT,
              date TEXT, 
              vulnerabilities TEXT, 
              status TEXT,
              scan_duration TEXT,
              FOREIGN KEY(user_id) REFERENCES users(id))''')
conn.commit()

# ========== МОДЕЛИ ==========
class RegisterRequest(BaseModel):
    username: str
    password: str
    email: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class ScanRequest(BaseModel):
    target_base_url: str
    openapi_url: Optional[str] = None

# ========== ФУНКЦИИ БЕЗОПАСНОСТИ ==========
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())
) -> dict:
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Неверные учётные данные")
        c.execute("SELECT id, username FROM users WHERE username=?", (username,))
        user = c.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="Пользователь не найден")
        return {"user_id": user[0], "username": user[1]}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Токен истёк")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Неверный токен")

# ========== AUTH ENDPOINTS ==========
@app.post("/auth/register", tags=["Авторизация"])
async def register(request: RegisterRequest):
    if len(request.username) < 3:
        raise HTTPException(status_code=400, detail="Логин ≥ 3 символов")
    if len(request.password) < 6:
        raise HTTPException(status_code=400, detail="Пароль ≥ 6 символов")
    try:
        c.execute("INSERT INTO users (username, password, email, created_at) VALUES (?, ?, ?, ?)",
                  (request.username, hash_password(request.password), request.email,
                   datetime.now().strftime("%Y-%m-%d %H:%M")))
        conn.commit()
        return {"status": "success", "message": "Регистрация завершена", "username": request.username}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Пользователь уже существует")

@app.post("/auth/login", tags=["Авторизация"])
async def login(request: LoginRequest):
    c.execute("SELECT id, username FROM users WHERE username=? AND password=?",
              (request.username, hash_password(request.password)))
    user = c.fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")
    access_token = create_access_token(data={"sub": request.username},
                                        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {
        "status": "success",
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user[0],
        "username": user[1],
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }

# ========== SCANNER ENDPOINTS ==========
@app.post("/scan", tags=["Сканирование"])
async def start_scan(request: ScanRequest, current_user: dict = Depends(verify_token)):
    from scanner.core import APIScanner
    from scanner.reporter import HTMLReporter
    
    if not request.target_base_url.startswith("http"):
        raise HTTPException(status_code=400, detail="URL должен начинаться с http:// или https://")
    
    start_time = datetime.now()
    scanner = APIScanner(request.target_base_url)
    findings = await scanner.run_scan()
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    c.execute("""INSERT INTO reports 
                 (user_id, target_url, openapi_url, date, vulnerabilities, status, scan_duration) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)""",
              (current_user["user_id"], request.target_base_url, request.openapi_url,
               datetime.now().strftime("%Y-%m-%d %H:%M"), str(findings), "completed", f"{duration:.2f} сек"))
    conn.commit()
    
    reporter = HTMLReporter(findings, request.target_base_url, current_user["username"])
    report_path = f"output/reports/scan_{current_user['user_id']}_{int(datetime.now().timestamp())}.html"
    reporter.save(report_path)
    
    return {
        "status": "completed",
        "target": request.target_base_url,
        "scanned_by": current_user["username"],
        "scan_duration": f"{duration:.2f} сек",
        "vulnerabilities_found": len(findings),
        "findings": findings,
        "report_id": c.lastrowid,
        "report_path": report_path
    }

@app.get("/reports", tags=["Отчёты"])
async def get_reports(current_user: dict = Depends(verify_token)):
    c.execute("SELECT id, target_url, date, vulnerabilities, status, scan_duration FROM reports WHERE user_id=?",
              (current_user["user_id"],))
    reports = c.fetchall()
    return {
        "user": current_user["username"],
        "total_reports": len(reports),
        "reports": [{"id": r[0], "target_url": r[1], "date": r[2], "status": r[4], "duration": r[5]} for r in reports]
    }

@app.get("/", tags=["Основное"])
async def root():
    return {
        "service": "API Security Scanner v1.0",
        "version": "1.0.0",
        "status": "running",
        "author": "Прутеану Мария, М24-505, МИФИ 2026",
        "docs": "/docs",
        "auth": "/auth/login"
    }

if __name__ == "__main__":
    print("=" * 60)
    print("🔍 API Security Scanner v1.0")
    print("📚 ВКР МИФИ 2026 - Прутеану Мария")
    print("=" * 60)
    print("\n🌐 Swagger UI: http://127.0.0.1:8000/docs")
    print("\n🚀 Запуск сервера...\n")
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)
