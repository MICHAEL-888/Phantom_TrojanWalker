from sqlalchemy import Column, Integer, String, JSON, DateTime, Text
from sqlalchemy.sql import func
from backend.database import Base


class AnalysisTask(Base):
    """Persisted analysis task and its decomposed results."""

    __tablename__ = "analysis_tasks"

    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(String, unique=True, index=True)  # UUID
    sha256 = Column(String, index=True)
    filename = Column(String)
    file_path = Column(String)  # Local path to stored binary
    status = Column(String, default="pending")  # pending, processing, completed, failed

    metadata_info = Column(JSON, nullable=True)
    malware_report = Column(JSON, nullable=True)

    error_message = Column(Text, nullable=True)  # If failed

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    # Refactor note: added server_default so updated_at is not NULL on insert.
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    finished_at = Column(DateTime(timezone=True), nullable=True)

