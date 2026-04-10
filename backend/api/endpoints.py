from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Form, Query
from fastapi.encoders import jsonable_encoder
from sqlalchemy.orm import Session, load_only
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

MAX_UPLOAD_BYTES = int(os.getenv("PTW_MAX_UPLOAD_BYTES", str(200 * 1024 * 1024)))  # 200MB default


def _validate_client_sha256(raw_sha256: str | None) -> str | None:
    """Validate optional client-provided sha256 and normalize casing."""
    if raw_sha256 is None:
        return None
    normalized = raw_sha256.strip().lower()
    if len(normalized) != 64 or any(c not in "0123456789abcdef" for c in normalized):
        raise HTTPException(status_code=400, detail="Invalid sha256 format")
    return normalized


def _safe_tmp_upload_path() -> str:
    """Create a temp upload path guarded against path traversal."""
    tmp_name = f".tmp_{uuid.uuid4().hex}"
    tmp_path = os.path.normpath(os.path.join(UPLOAD_DIR, tmp_name))
    if os.path.commonpath([UPLOAD_DIR, tmp_path]) != UPLOAD_DIR:
        raise HTTPException(status_code=400, detail="Invalid upload path")
    return tmp_path


def _remove_file_quietly(path: str) -> None:
    """Best-effort file deletion to avoid masking primary errors."""
    try:
        os.remove(path)
    except OSError:
        pass


async def _stream_to_temp_file(file: UploadFile, tmp_path: str) -> str:
    """Stream upload to temp file while computing sha256.

    Refactor note: keep streaming + size checks in one place for clarity.
    """
    hasher = hashlib.sha256()
    total = 0
    async with aiofiles.open(tmp_path, "wb") as out_file:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                # Guard clause keeps overflow handling close to size check.
                try:
                    await out_file.close()
                finally:
                    _remove_file_quietly(tmp_path)
                raise HTTPException(status_code=413, detail="File too large")
            hasher.update(chunk)
            await out_file.write(chunk)
    return hasher.hexdigest()


def _resolve_final_upload_path(sha256: str) -> str:
    """Resolve final upload path by sha256 with path traversal guard."""
    file_path = os.path.normpath(os.path.join(UPLOAD_DIR, sha256))
    if os.path.commonpath([UPLOAD_DIR, file_path]) != UPLOAD_DIR:
        raise HTTPException(status_code=400, detail="Invalid filename")
    return file_path


def _persist_upload(tmp_path: str, sha256: str) -> str:
    """Move temp file into final path, handling collisions safely."""
    file_path = _resolve_final_upload_path(sha256)
    try:
        if os.path.exists(file_path):
            _remove_file_quietly(tmp_path)
        else:
            os.replace(tmp_path, file_path)
    except OSError as e:
        _remove_file_quietly(tmp_path)
        raise HTTPException(status_code=500, detail=f"Failed to store upload: {e}")
    return file_path


def _find_existing_task(db: Session, sha256: str) -> AnalysisTask | None:
    """Return existing task by sha256 (pending/processing/completed)."""
    return (
        db.query(AnalysisTask)
        .filter(
            AnalysisTask.sha256 == sha256,
            AnalysisTask.status.in_(["completed", "pending", "processing"]),
        )
        .first()
    )


def _task_summary_payload(task: AnalysisTask, include_heavy: bool = True) -> dict:
    """Build response payload for task summary endpoints.

    include_heavy=False omits large JSON columns to speed up detail polling.
    """
    payload = {
        "task_id": task.task_id,
        "status": task.status,
        "sha256": task.sha256,
        "filename": task.filename,
        "metadata": task.metadata_info,
        "malware_report": task.malware_report,
        "error": task.error_message,
        "created_at": task.created_at,
        "finished_at": task.finished_at,
    }
    if include_heavy:
        payload.update(
            {
                "functions": task.functions,
                "strings": task.strings,
                "decompiled_code": task.decompiled_code,
                "function_xrefs": task.function_xrefs,
                "function_analyses": task.function_analyses,
            }
        )
    return payload


def _task_query(db: Session, include_heavy: bool):
    """Build a task query that can skip heavy JSON columns when unnecessary."""
    query = db.query(AnalysisTask)
    if include_heavy:
        return query

    return query.options(
        load_only(
            AnalysisTask.task_id,
            AnalysisTask.status,
            AnalysisTask.sha256,
            AnalysisTask.filename,
            AnalysisTask.metadata_info,
            AnalysisTask.malware_report,
            AnalysisTask.error_message,
            AnalysisTask.created_at,
            AnalysisTask.finished_at,
        )
    )


def _history_entry_payload(task: AnalysisTask) -> dict:
    """Create JSON-serializable summary for history list."""
    return {
        "task_id": task.task_id,
        "status": task.status,
        "sha256": task.sha256,
        "filename": task.filename,
        "created_at": task.created_at,
        "finished_at": task.finished_at,
        "error": task.error_message,
    }

@router.post("/analyze")
async def analyze_file(
    file: UploadFile = File(...),
    sha256: str | None = Form(None),
    db: Session = Depends(get_db),
):
    # Validate optional client-provided sha256, but always compute server-side.
    client_sha256 = _validate_client_sha256(sha256)

    # Stream upload: write temp file + compute sha256 incrementally.
    tmp_path = _safe_tmp_upload_path()
    sha256 = await _stream_to_temp_file(file, tmp_path)

    if client_sha256 and client_sha256 != sha256:
        _remove_file_quietly(tmp_path)
        raise HTTPException(status_code=400, detail="sha256 mismatch")

    # Check if exists (any active or completed task)
    existing_task = _find_existing_task(db, sha256)
    if existing_task:
        _remove_file_quietly(tmp_path)
        return {
            "task_id": existing_task.task_id,
            "status": existing_task.status,
            "message": f"Analysis already {existing_task.status}.",
            "sha256": sha256,
        }

    # Save file by sha256 (stable + safe filename)
    file_path = _persist_upload(tmp_path, sha256)
        
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
        "sha256": sha256,
    }

@router.get("/tasks/{task_id}")
def get_task_status(
    task_id: str,
    include_heavy: bool = False,
    db: Session = Depends(get_db),
):
    task = _task_query(db, include_heavy=include_heavy).filter(AnalysisTask.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return _task_summary_payload(task, include_heavy=include_heavy)

@router.get("/result/{sha256}")
def get_result_by_hash(
    sha256: str,
    include_heavy: bool = False,
    db: Session = Depends(get_db),
):
    task = (
        _task_query(db, include_heavy=include_heavy)
        .filter(AnalysisTask.sha256 == sha256)
        .order_by(desc(AnalysisTask.created_at))
        .first()
    )
    if not task:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    payload = _task_summary_payload(task, include_heavy=include_heavy)
    # Keep legacy behavior: omit timestamps in hash lookup response.
    payload.pop("created_at", None)
    payload.pop("finished_at", None)
    return payload

@router.get("/history")
def get_recent_history(limit: int = Query(10, ge=1, le=200), db: Session = Depends(get_db)):
    tasks = (
        db.query(AnalysisTask)
        .options(
            load_only(
                AnalysisTask.task_id,
                AnalysisTask.status,
                AnalysisTask.sha256,
                AnalysisTask.filename,
                AnalysisTask.created_at,
                AnalysisTask.finished_at,
                AnalysisTask.error_message,
            )
        )
        .order_by(desc(AnalysisTask.created_at))
        .limit(limit)
        .all()
    )
    # Return a JSON-serializable summary (avoid leaking internal fields/paths).
    payload = [_history_entry_payload(t) for t in tasks]
    return jsonable_encoder(payload)
