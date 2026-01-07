from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
import hashlib
import os
import uuid
import aiofiles

from backend.database import get_db, DB_DIR
from backend.models.task import AnalysisTask
from backend.worker.worker import worker

router = APIRouter()

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "uploads")
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

def calculate_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

@router.post("/analyze")
async def analyze_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()
    sha256 = calculate_sha256(content)
    
    # Check if exists
    existing_task = db.query(AnalysisTask).filter(AnalysisTask.sha256 == sha256, AnalysisTask.status == "completed").first()
    if existing_task:
        return {
            "task_id": existing_task.task_id,
            "status": "completed",
            "message": "Analysis already exists.",
            "sha256": sha256
        }
    
    # Save file
    file_path = os.path.join(UPLOAD_DIR, f"{sha256}_{file.filename}")
    # Write async
    async with aiofiles.open(file_path, 'wb') as out_file:
        await out_file.write(content)
        
    # Create Task
    task_uuid = str(uuid.uuid4())
    new_task = AnalysisTask(
        task_id=task_uuid,
        sha256=sha256,
        filename=file.filename,
        file_path=file_path,
        status="pending"
    )
    db.add(new_task)
    db.commit()
    db.refresh(new_task)
    
    # Enqueue
    worker.add_task(new_task.id)
    
    return {
        "task_id": task_uuid,
        "status": "pending",
        "message": "Analysis queued.",
        "sha256": sha256
    }

@router.get("/tasks/{task_id}")
def get_task_status(task_id: str, db: Session = Depends(get_db)):
    task = db.query(AnalysisTask).filter(AnalysisTask.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return {
        "task_id": task.task_id,
        "status": task.status,
        "filename": task.filename,
        "result": task.result,
        "error": task.error_message,
        "created_at": task.created_at,
        "finished_at": task.finished_at
    }

@router.get("/result/{sha256}")
def get_result_by_hash(sha256: str, db: Session = Depends(get_db)):
    task = db.query(AnalysisTask).filter(AnalysisTask.sha256 == sha256).order_by(desc(AnalysisTask.created_at)).first()
    if not task:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    return {
        "task_id": task.task_id,
        "status": task.status,
        "result": task.result
    }

@router.get("/history")
def get_recent_history(limit: int = 10, db: Session = Depends(get_db)):
    tasks = db.query(AnalysisTask).order_by(desc(AnalysisTask.created_at)).limit(limit).all()
    return tasks
