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
    result = Column(JSON, nullable=True) # The final analysis report
    error_message = Column(Text, nullable=True) # If failed
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
