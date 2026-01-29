from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Form
from sqlalchemy.orm import Session
from sqlalchemy import desc
import hashlib
import os
import uuid
import aiofiles

from backend.database import get_db
from backend.models.task import AnalysisTask
from backend.worker.worker import worker

router = APIRouter()

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
UPLOAD_DIR = os.path.join(ROOT_DIR, "data", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

def calculate_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

@router.post("/analyze")
async def analyze_file(
    file: UploadFile = File(...),
    sha256: str | None = Form(None),
    db: Session = Depends(get_db),
):
    # Prefer client-provided sha256 to avoid server-side hashing work.
    # NOTE: This trusts the client hash. If you need integrity, enable a server-side
    # verification path (not enabled by default).
    if sha256 is not None:
        sha256 = sha256.strip().lower()
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise HTTPException(status_code=400, detail="Invalid sha256 format")
    else:
        content = await file.read()
        sha256 = calculate_sha256(content)
    
    # Check if exists (any active or completed task)
    existing_task = db.query(AnalysisTask).filter(
        AnalysisTask.sha256 == sha256, 
        AnalysisTask.status.in_(["completed", "pending", "processing"])
    ).first()
    
    if existing_task:
        return {
            "task_id": existing_task.task_id,
            "status": existing_task.status,
            "message": f"Analysis already {existing_task.status}.",
            "sha256": sha256
        }
    
    # Save file
    file_path = os.path.join(UPLOAD_DIR, f"{sha256}_{file.filename}")
    # Write async (stream when sha256 provided to avoid buffering whole file)
    async with aiofiles.open(file_path, "wb") as out_file:
        if "content" in locals():
            await out_file.write(content)
        else:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                await out_file.write(chunk)
        
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
        "sha256": task.sha256,
        "filename": task.filename,
        "metadata": task.metadata_info,
        "functions": task.functions,
        "strings": task.strings,
        "decompiled_code": task.decompiled_code,
        "function_analyses": task.function_analyses,
        "malware_report": task.malware_report,
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
        "sha256": task.sha256,
        "filename": task.filename,
        "metadata": task.metadata_info,
        "functions": task.functions,
        "strings": task.strings,
        "decompiled_code": task.decompiled_code,
        "function_analyses": task.function_analyses,
        "malware_report": task.malware_report
    }

@router.get("/history")
def get_recent_history(limit: int = 10, db: Session = Depends(get_db)):
    tasks = db.query(AnalysisTask).order_by(desc(AnalysisTask.created_at)).limit(limit).all()
    return tasks
