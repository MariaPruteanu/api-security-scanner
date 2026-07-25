import os
import json
import uuid
import asyncio
import tempfile
import shutil
from datetime import datetime
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="API Security Scanner",
    description="Сканирование OpenAPI/Swagger/Postman спецификаций",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scan_tasks: Dict[str, Dict[str, Any]] = {}

class ScanSubmit(BaseModel):
    target: str
    scan_type: str = "basic"

class ScanStatus(BaseModel):
    task_id: str
    status: str
    progress: int = 0
    error: Optional[str] = None

class ScanResult(BaseModel):
    task_id: str
    results: List[Dict[str, Any]]

async def run_scan_task(task_id: str, target: str, scan_type: str):
    try:
        scan_tasks[task_id]["status"] = "running"
        scan_tasks[task_id]["progress"] = 10
        
        from scanner.core import APIScanner
        
        scanner = APIScanner(base_url=target, scan_type=scan_type)
        scan_tasks[task_id]["progress"] = 30
        
        results = await scanner.run_scan()
        scan_tasks[task_id]["progress"] = 90
        
        scan_tasks[task_id]["status"] = "completed"
        scan_tasks[task_id]["progress"] = 100
        scan_tasks[task_id]["results"] = results
        
        logger.info(f"✅ Сканирование {task_id} завершено, найдено {len(results)} уязвимостей")
        
    except Exception as e:
        logger.error(f"❌ Ошибка сканирования {task_id}: {e}")
        scan_tasks[task_id]["status"] = "failed"
        scan_tasks[task_id]["error"] = str(e)

@app.get("/")
async def root():
    return {"message": "API Security Scanner is running", "docs": "/docs"}

@app.post("/api/v1/scan/submit")
async def submit_scan(data: ScanSubmit):
    task_id = str(uuid.uuid4())
    scan_tasks[task_id] = {
        "task_id": task_id,
        "target": data.target,
        "scan_type": data.scan_type,
        "status": "pending",
        "progress": 0,
        "created_at": datetime.now().isoformat(),
        "results": None,
        "error": None
    }
    
    asyncio.create_task(run_scan_task(task_id, data.target, data.scan_type))
    
    return {"task_id": task_id, "status": "pending"}

@app.get("/api/v1/scan/status/{task_id}")
async def get_status(task_id: str):
    if task_id not in scan_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    task = scan_tasks[task_id]
    return {
        "task_id": task_id,
        "status": task["status"],
        "progress": task["progress"],
        "error": task.get("error")
    }

@app.get("/api/v1/scan/result/{task_id}")
async def get_result(task_id: str):
    if task_id not in scan_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    task = scan_tasks[task_id]
    if task["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed yet")
    return {
        "task_id": task_id,
        "results": task.get("results", [])
    }

@app.post("/api/scan")
async def scan_file(file: UploadFile = File(...)):
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name
        
        scan_type = "basic"
        
        from scanner.core import APIScanner
        scanner = APIScanner(base_url=tmp_path, scan_type=scan_type)
        results = await scanner.run_scan()
        
        os.unlink(tmp_path)
        
        return {"results": results}
        
    except Exception as e:
        logger.error(f"Ошибка сканирования файла: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "ok", "tasks": len(scan_tasks)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
from defi_payment import defi

@app.get("/api/payment/defi/info")
async def get_defi_payment_info():
    """Возвращает информацию для оплаты через DeFi."""
    return defi.get_payment_info()

@app.post("/api/payment/defi/check")
async def check_defi_payment(tx_hash: str):
    """Проверяет статус транзакции."""
    return defi.check_payment(tx_hash)

@app.post("/api/payment/defi/check")
async def check_defi_payment():
    """Проверяет, была ли оплата на DeFi-кошелёк."""
    from solana_checker import checker
    success, tx_hash, message = checker.check_payment()
    return {
        "success": success,
        "tx_hash": tx_hash,
        "message": message
    }

@app.get("/api/payment/defi/info")
async def get_defi_payment_info(period: str = "monthly"):
    """Возвращает информацию для оплаты через DeFi."""
    from defi_payment import defi
    return defi.get_payment_info(period)

@app.post("/api/payment/defi/check")
async def check_defi_payment(tx_hash: str):
    from defi_payment import defi
    return defi.check_payment(tx_hash)

@app.get("/api/payment/defi/info")
async def get_defi_payment_info(plan: str = "monthly"):
    """Возвращает информацию для оплаты через DeFi."""
    from defi_payment import defi
    return defi.get_payment_info(plan)

@app.post("/api/payment/defi/check")
async def check_defi_payment():
    """Проверяет, была ли оплата на DeFi-кошелёк."""
    from solana_checker import checker
    success, tx_hash, message = checker.check_payment()
    return {
        "success": success,
        "tx_hash": tx_hash,
        "message": message
    }

@app.post("/api/payment/defi/check")
async def check_defi_payment(tx_hash: str):
    """Проверяет, была ли оплата на DeFi-кошелёк."""
    from solana_checker import checker
    success, tx_hash_res, message = checker.check_payment(tx_hash)
    return {
        "success": success,
        "tx_hash": tx_hash,
        "message": message
    }
