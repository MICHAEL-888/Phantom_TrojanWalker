import asyncio
import logging
import json
import traceback
from datetime import datetime
from sqlalchemy.orm import Session

from backend.database import SessionLocal
from backend.models.task import AnalysisTask
from backend.core.factory import create_coordinator

logger = logging.getLogger(__name__)

class AnalysisWorker:
    def __init__(self):
        self.queue = asyncio.Queue()
        self.coordinator = None
        self._running = False
        self._analysis_lock = asyncio.Lock() # Explicit lock to ensure only one analysis runs at a time

    async def start(self):
        self.coordinator = create_coordinator()
        self._running = True
        logger.info("AnalysisWorker started.")
        asyncio.create_task(self.process_queue())

    async def process_queue(self):
        while self._running:
            task_id = await self.queue.get()
            try:
                # Use lock to strictly enforce single analysis
                async with self._analysis_lock:
                    await self.run_analysis(task_id)
            except Exception as e:
                logger.error(f"Error processing task {task_id}: {e}")
            finally:
                self.queue.task_done()

    async def run_analysis(self, task_id: int):
        db: Session = SessionLocal()
        try:
            task = db.query(AnalysisTask).filter(AnalysisTask.id == task_id).first()
            if not task:
                logger.error(f"Task {task_id} not found in DB.")
                return

            logger.info(f"Processing task {task.task_id} ({task.filename})")
            task.status = "processing"
            db.commit()

            # Read file content
            try:
                with open(task.file_path, "rb") as f:
                    content = f.read()
            except FileNotFoundError:
                task.status = "failed"
                task.error_message = "File not found on disk."
                db.commit()
                return

            # Run analysis
            try:
                result = await self.coordinator.analyze_content(task.filename, content)
                task.status = "completed"
                
                # Unpack result into columns
                task.metadata_info = result.get("metadata")
                task.functions = result.get("functions")
                task.strings = result.get("strings")
                task.decompiled_code = result.get("decompiled_code")
                task.function_analyses = result.get("function_analyses")
                task.malware_report = result.get("malware_report")

                task.finished_at = datetime.now()
            except Exception as e:
                logger.error(f"Analysis failed: {traceback.format_exc()}")
                task.status = "failed"
                task.error_message = str(e)
            
            db.commit()

        except Exception as e:
            logger.error(f"Worker DB Error: {e}")
        finally:
            db.close()

    def add_task(self, task_id: int):
        self.queue.put_nowait(task_id)

worker = AnalysisWorker()
