import os
import secrets
import asyncio
import json
import uuid
from fastapi import FastAPI, Depends, HTTPException, Header, Request
from sqlalchemy.orm import Session
from datetime import datetime
from pydantic import BaseModel
import uvicorn

# Импорты из корневых модулей (без точек)
from database import get_db, User, ScanTask
import scanner_worker   # ваш сканер

app = FastAPI(title="API Security Scanner Cloud", version="1.0")

class ScanSubmit(BaseModel):
    target: str
    scan_type: str = "basic"

# ------------------------------------------------------------
# Тестовый эндпоинт регистрации (выдаёт API-ключ)
# ------------------------------------------------------------
@app.post("/api/v1/register-test")
def register_test(email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if user:
        return {"api_key": user.api_key, "status": "active"}
    new_user = User(
        email=email,
        api_key=secrets.token_urlsafe(32),
        subscription_active=True
    )
    db.add(new_user)
    db.commit()
    return {"api_key": new_user.api_key, "status": "active"}

# ------------------------------------------------------------
# Запуск сканирования (асинхронный)
# ------------------------------------------------------------
@app.post("/api/v1/scan/submit")
async def submit_scan(
    payload: ScanSubmit,
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    api_key = authorization.replace("Bearer ", "")
    user = db.query(User).filter(User.api_key == api_key).first()
    if not user or not user.subscription_active:
        raise HTTPException(401, "Invalid or expired API key")
    
    task_id = str(uuid.uuid4())
    new_task = ScanTask(
        task_id=task_id,
        user_id=user.id,
        target=payload.target,
        status="pending"
    )
    db.add(new_task)
    db.commit()
    
    # Передаём scan_type в фоновую задачу
    asyncio.create_task(process_scan(task_id, payload.target, payload.scan_type))
    return {"task_id": task_id, "status": "pending"}

async def process_scan(task_id: str, target: str, scan_type: str = "basic"):
    from database import SessionLocal
    db = SessionLocal()
    task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
    if not task:
        return
    try:
        task.status = "running"
        task.progress = 10
        db.commit()
        # Передаём scan_type в сканер
        result = await scanner_worker.run_scan(target, scan_type)
        task.status = "completed"
        task.progress = 100
        task.result = json.dumps(result, ensure_ascii=False)
        db.commit()
    except Exception as e:
        task.status = "failed"
        task.error = str(e)
        db.commit()
    finally:
        db.close()

# ------------------------------------------------------------
# Статус
# ------------------------------------------------------------
@app.get("/api/v1/scan/status/{task_id}")
def get_status(task_id: str, db: Session = Depends(get_db)):
    task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
    if not task:
        raise HTTPException(404, "Task not found")
    return {
        "task_id": task.task_id,
        "status": task.status,
        "progress": task.progress,
        "error": task.error
    }

# ------------------------------------------------------------
# Результат
# ------------------------------------------------------------
@app.get("/api/v1/scan/result/{task_id}")
def get_result(task_id: str, db: Session = Depends(get_db)):
    task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
    if not task or task.status != "completed":
        raise HTTPException(404, "Result not ready")
    return json.loads(task.result)

# ------------------------------------------------------------
# Запуск
# ------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)