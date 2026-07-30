"""HTTP API endpoints for task upload, polling, and history.

Refactor note: the 53-line analyze_file is decomposed into named helpers.
Sync DB/file I/O in the async endpoint is wrapped in run_in_threadpool to
avoid blocking the event loop. Orphaned temp files and persisted files are
cleaned up on failure paths. Status magic strings replaced by shared constants.
"""
import hashlib
import os
import uuid

import aiofiles
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Form, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.encoders import jsonable_encoder
from sqlalchemy import desc
from sqlalchemy.orm import Session, load_only

from backend.database import get_db
from backend.models.task import AnalysisTask
from backend.status import ACTIVE_STATUSES, STATUS_PENDING
from backend.worker.worker import worker

router = APIRouter()

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
UPLOAD_DIR = os.path.join(ROOT_DIR, "data", "uploads")

MAX_UPLOAD_BYTES = int(os.getenv("PTW_MAX_UPLOAD_BYTES", str(200 * 1024 * 1024)))  # 200MB default
_CHUNK_SIZE = 1024 * 1024


def ensure_upload_dir() -> None:
    """Create the upload directory (called from app lifespan, not at import)."""
    os.makedirs(UPLOAD_DIR, exist_ok=True)


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
            chunk = await file.read(_CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                # Guard clause keeps overflow handling close to size check.
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
            AnalysisTask.status.in_(ACTIVE_STATUSES),
        )
        .first()
    )


def _dedup_or_persist_and_create_task(
    db: Session, tmp_path: str, sha256: str, filename: str | None,
) -> dict:
    """Dedup check + persist + create task row (sync, runs in threadpool).

    Refactor note: groups all sync DB/file I/O so it can run in a threadpool
    without blocking the event loop. On DB failure after persist, the orphaned
    file is cleaned up.
    """
    existing_task = _find_existing_task(db, sha256)
    if existing_task:
        _remove_file_quietly(tmp_path)
        return {
            "existing": True,
            "task_id": existing_task.task_id,
            "status": existing_task.status,
        }

    file_path = _persist_upload(tmp_path, sha256)

    try:
        task_uuid = str(uuid.uuid4())
        new_task = AnalysisTask(
            task_id=task_uuid,
            sha256=sha256,
            filename=filename,
            file_path=file_path,
            status=STATUS_PENDING,
        )
        db.add(new_task)
        db.commit()
        db.refresh(new_task)
        return {"existing": False, "task_id": task_uuid, "id": new_task.id}
    except Exception:
        # Refactor note: clean up the persisted file if DB commit fails, so we
        # don't leak orphaned files on disk with no DB row referencing them.
        db.rollback()
        _remove_file_quietly(file_path)
        raise


def _task_summary_payload(task: AnalysisTask) -> dict:
    return {
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
    """Upload a binary, dedup by sha256, create a task, and enqueue it.

    Refactor note: decomposed from a 53-line function. Sync DB/file I/O runs
    in a threadpool. The outer try/finally ensures temp file cleanup on any
    exception path (prevents orphaned .tmp_ files on disk-full/permission errors).
    """
    client_sha256 = _validate_client_sha256(sha256)

    tmp_path = _safe_tmp_upload_path()
    try:
        computed_sha256 = await _stream_to_temp_file(file, tmp_path)

        if client_sha256 and client_sha256 != computed_sha256:
            raise HTTPException(status_code=400, detail="sha256 mismatch")

        # Refactor note: run sync DB + file I/O in threadpool to avoid blocking
        # the event loop during SQLite queries and os.replace.
        result = await run_in_threadpool(
            _dedup_or_persist_and_create_task, db, tmp_path, computed_sha256, file.filename,
        )

        if result["existing"]:
            return {
                "task_id": result["task_id"],
                "status": result["status"],
                "message": f"Analysis already {result['status']}.",
                "sha256": computed_sha256,
            }

        # Enqueue must happen on the event loop thread (asyncio.Queue is not thread-safe).
        worker.add_task(result["id"])
        return {
            "task_id": result["task_id"],
            "status": STATUS_PENDING,
            "message": "Analysis queued.",
            "sha256": computed_sha256,
        }
    finally:
        # Refactor note: ensure temp file is cleaned up on any exception path.
        # If persist succeeded, tmp_path no longer exists and this is a no-op.
        _remove_file_quietly(tmp_path)


@router.get("/tasks/{task_id}")
def get_task_status(
    task_id: str,
    db: Session = Depends(get_db),
):
    task = db.query(AnalysisTask).filter(AnalysisTask.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    return _task_summary_payload(task)


@router.get("/result/{sha256}")
def get_result_by_hash(
    sha256: str,
    db: Session = Depends(get_db),
):
    task = (
        db.query(AnalysisTask)
        .filter(AnalysisTask.sha256 == sha256)
        .order_by(desc(AnalysisTask.created_at))
        .first()
    )
    if not task:
        raise HTTPException(status_code=404, detail="Analysis not found")

    payload = _task_summary_payload(task)
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
    payload = [_history_entry_payload(t) for t in tasks]
    return jsonable_encoder(payload)
