"""
FastAPI бэкенд для API Security Scanner
Поддерживает эндпоинты, ожидаемые GUI (CloudScanner)
"""
import asyncio
import uuid
import time
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any
import uvicorn

# --- Модели данных ---
class ScanRequest(BaseModel):
    target: str
    scan_type: str = "basic"

class ScanResponse(BaseModel):
    task_id: str

class StatusResponse(BaseModel):
    task_id: str
    status: str          # "pending", "running", "completed", "failed"
    progress: int        # 0-100
    error: Optional[str] = None

class ResultResponse(BaseModel):
    task_id: str
    results: list

# --- Хранилище задач (в памяти) ---
tasks: Dict[str, Dict[str, Any]] = {}

# --- Функция сканирования (заглушка, но можно заменить на реальную) ---
async def run_scan(target: str, scan_type: str) -> list:
    """Имитация сканирования. Возвращает список находок."""
    # Эмулируем долгую работу
    await asyncio.sleep(2)
    
    base_findings = [
        {"id": "1", "severity": "HIGH", "description": f"Тестовая уязвимость в {target}"},
        {"id": "2", "severity": "MEDIUM", "description": "Отсутствует HSTS"},
        {"id": "3", "severity": "LOW", "description": "Доступен отладочный эндпоинт"},
    ]
    premium_findings = [
        {"id": "4", "severity": "HIGH", "description": "SQL-инъекция в параметре id"},
        {"id": "5", "severity": "MEDIUM", "description": "Недостаточное логирование"},
    ]
    enterprise_findings = [
        {"id": "6", "severity": "CRITICAL", "description": "SSRF в эндпоинте /fetch"},
        {"id": "7", "severity": "HIGH", "description": "Mass Assignment в /users"},
        {"id": "8", "severity": "MEDIUM", "description": "Отсутствие rate limiting"},
    ]
    if scan_type == "basic":
        return base_findings
    elif scan_type == "premium":
        return base_findings + premium_findings
    elif scan_type == "enterprise":
        return base_findings + premium_findings + enterprise_findings
    else:
        return base_findings

# --- FastAPI приложение ---
app = FastAPI(
    title="API Security Scanner",
    description="Бэкенд для сканирования API-уязвимостей",
    version="1.0"
)

# --- Эндпоинты ---
@app.post("/api/v1/scan/submit", response_model=ScanResponse)
async def submit_scan(request: ScanRequest, authorization: Optional[str] = Header(None)):
    """Принимает задание на сканирование, возвращает task_id."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid API key")
    
    task_id = str(uuid.uuid4())
    tasks[task_id] = {
        "status": "pending",
        "progress": 0,
        "target": request.target,
        "scan_type": request.scan_type,
        "error": None,
        "results": None
    }
    # Запускаем фоновую задачу
    asyncio.create_task(process_scan(task_id, request.target, request.scan_type))
    return ScanResponse(task_id=task_id)

@app.get("/api/v1/scan/status/{task_id}", response_model=StatusResponse)
async def get_status(task_id: str):
    """Возвращает статус сканирования."""
    task = tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return StatusResponse(
        task_id=task_id,
        status=task["status"],
        progress=task["progress"],
        error=task.get("error")
    )

@app.get("/api/v1/scan/result/{task_id}", response_model=ResultResponse)
async def get_result(task_id: str):
    """Возвращает результаты сканирования."""
    task = tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed yet")
    return ResultResponse(task_id=task_id, results=task["results"])

# --- Фоновая задача ---
async def process_scan(task_id: str, target: str, scan_type: str):
    """Выполняет сканирование в фоне."""
    try:
        tasks[task_id]["status"] = "running"
        tasks[task_id]["progress"] = 10
        await asyncio.sleep(1)  # имитация работы
        
        tasks[task_id]["progress"] = 50
        results = await run_scan(target, scan_type)
        
        tasks[task_id]["progress"] = 100
        tasks[task_id]["status"] = "completed"
        tasks[task_id]["results"] = results
    except Exception as e:
        tasks[task_id]["status"] = "failed"
        tasks[task_id]["error"] = str(e)
        tasks[task_id]["progress"] = 0

# --- Корневой эндпоинт для проверки ---
@app.get("/")
async def root():
    return {"message": "API Security Scanner is running", "docs": "/docs"}

# --- Точка входа для uvicorn (если запускаем напрямую) ---
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
