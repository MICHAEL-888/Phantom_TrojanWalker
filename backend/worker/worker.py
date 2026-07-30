"""Analysis worker: async queue + single-concurrency lock.

Refactor note: fixes folded in:
- worker.stop() for graceful shutdown (lifespan can now stop the consumer).
- finished_at now uses timezone-aware UTC (was naive local time).
- Outer except in run_analysis marks the task failed (was only logging, leaving
  tasks stuck in "processing" until restart).
- db.commit() in the finally block is wrapped in its own try so a commit
  failure doesn't swallow the already-set failed status.
- Status magic strings replaced by shared constants.
"""
import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from backend.database import SessionLocal
from backend.models.task import AnalysisTask
from backend.core.factory import create_coordinator
from backend.status import (
    STATUS_PENDING,
    STATUS_PROCESSING,
    STATUS_COMPLETED,
    STATUS_FAILED,
    UNFINISHED_STATUSES,
)

logger = logging.getLogger(__name__)


class AnalysisWorker:
    def __init__(self):
        self.queue = asyncio.Queue()
        self.coordinator = None
        self._running = False
        self._analysis_lock = asyncio.Lock()
        self._consumer_task = None

    def _requeue_unfinished_tasks(self):
        db: Session = SessionLocal()
        try:
            tasks = (
                db.query(AnalysisTask)
                .filter(AnalysisTask.status.in_(UNFINISHED_STATUSES))
                .order_by(AnalysisTask.created_at.asc())
                .all()
            )
            if not tasks:
                return

            for t in tasks:
                if t.status == STATUS_PROCESSING:
                    t.status = STATUS_PENDING
            db.commit()

            for t in tasks:
                self.queue.put_nowait(t.id)
            logger.info("Re-queued %d unfinished task(s) on startup.", len(tasks))
        except Exception:
            logger.error("Failed to re-queue unfinished tasks on startup", exc_info=True)
        finally:
            db.close()

    async def start(self):
        self.coordinator = create_coordinator()
        self._running = True
        logger.info("AnalysisWorker started.")
        self._requeue_unfinished_tasks()
        self._consumer_task = asyncio.create_task(self.process_queue())

    async def stop(self):
        """Graceful shutdown: stop consuming and let the current task finish.

        Refactor note: previously _running was never set to False and the
        consumer was cancelled mid-flight by loop shutdown, which could leave
        Ghidra's global state inconsistent.
        """
        self._running = False
        if self._consumer_task and not self._consumer_task.done():
            self._consumer_task.cancel()
            try:
                await self._consumer_task
            except asyncio.CancelledError:
                pass
        logger.info("AnalysisWorker stopped.")

    async def process_queue(self):
        while self._running:
            task_id = await self.queue.get()
            try:
                async with self._analysis_lock:
                    await self.run_analysis(task_id)
            except Exception as e:
                logger.error("Error processing task %s: %s", task_id, e)
            finally:
                self.queue.task_done()

    async def run_analysis(self, task_id: int):
        db: Session = SessionLocal()
        try:
            task = self._fetch_task(db, task_id)
            if not task:
                return

            self._mark_processing(task, db)

            content = self._read_file_content(task, db)
            if content is None:
                return

            await self._run_analysis_pipeline(task, content, db)
        except Exception as e:
            # Refactor note: mark the task failed instead of only logging.
            # Previously a DB error here left the task stuck in "processing".
            logger.error("Worker error for task %s: %s", task_id, e)
            self._safe_mark_failed(db, task_id, str(e))
        finally:
            db.close()

    def _fetch_task(self, db: Session, task_id: int) -> AnalysisTask | None:
        """Fetch task row and handle missing record.

        Refactor note: keep DB lookup logic in one place.
        """
        task = db.query(AnalysisTask).filter(AnalysisTask.id == task_id).first()
        if not task:
            logger.error("Task %s not found in DB.", task_id)
            return None
        return task

    def _mark_processing(self, task: AnalysisTask, db: Session) -> None:
        """Mark task as processing and persist immediately."""
        logger.info("Processing task %s (%s)", task.task_id, task.filename)
        task.status = STATUS_PROCESSING
        db.commit()

    def _read_file_content(self, task: AnalysisTask, db: Session) -> bytes | None:
        """Read binary content from disk and persist error on failure."""
        try:
            with open(task.file_path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            # Guard clause keeps error handling close to the failure.
            task.status = STATUS_FAILED
            task.error_message = "File not found on disk."
            db.commit()
            return None

    async def _run_analysis_pipeline(self, task: AnalysisTask, content: bytes, db: Session) -> None:
        """Run analysis pipeline and update task fields.

        Refactor note: isolate the analysis path from DB orchestration.
        """
        try:
            result = await self.coordinator.analyze_content(task.sha256, content)
            task.status = STATUS_COMPLETED

            task.metadata_info = result.get("metadata")
            task.functions = result.get("functions")
            task.strings = result.get("strings")
            task.decompiled_code = result.get("decompiled_code")
            task.function_xrefs = result.get("function_xrefs")
            task.function_analyses = result.get("function_analyses")
            task.malware_report = result.get("malware_report")

            # Refactor note: use timezone-aware UTC to match created_at's
            # server_default=func.now() reference frame.
            task.finished_at = datetime.now(timezone.utc)
        except Exception as e:
            logger.error(
                "Analysis failed for task %s (%s): %s",
                task.task_id, task.filename, e, exc_info=True,
            )
            task.status = STATUS_FAILED
            task.error_message = str(e) or "Analysis failed."
        finally:
            # Refactor note: wrap commit in its own try so a commit failure
            # doesn't swallow the already-set failed status silently.
            try:
                db.commit()
            except Exception as commit_err:
                logger.error("Failed to commit task %s state: %s", task.task_id, commit_err)
                db.rollback()

    def _safe_mark_failed(self, db: Session, task_id: int, error_message: str) -> None:
        """Best-effort mark a task as failed (used by the outer except)."""
        try:
            task = db.query(AnalysisTask).filter(AnalysisTask.id == task_id).first()
            if task:
                task.status = STATUS_FAILED
                task.error_message = error_message or "Analysis failed."
                db.commit()
        except Exception:
            logger.error("Failed to mark task %s as failed.", task_id, exc_info=True)
            try:
                db.rollback()
            except Exception:
                pass

    def add_task(self, task_id: int):
        self.queue.put_nowait(task_id)


worker = AnalysisWorker()
