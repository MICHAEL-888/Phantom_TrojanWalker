from sqlalchemy import Column, Integer, String, JSON, DateTime, Text
from sqlalchemy.sql import func
from backend.database import Base
import datetime

class AnalysisTask(Base):
    __tablename__ = "analysis_tasks"

    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(String, unique=True, index=True) # UUID
    sha256 = Column(String, index=True)
    filename = Column(String)
    file_path = Column(String) # Local path to stored binary
    status = Column(String, default="pending") # pending, processing, completed, failed
    
    # Split results
    metadata_info = Column(JSON, nullable=True) 
    functions = Column(JSON, nullable=True)
    strings = Column(JSON, nullable=True)
    decompiled_code = Column(JSON, nullable=True)
    function_analyses = Column(JSON, nullable=True)
    malware_report = Column(JSON, nullable=True)

    error_message = Column(Text, nullable=True) # If failed
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    finished_at = Column(DateTime(timezone=True), nullable=True)

