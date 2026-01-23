from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
import shutil

# Store all persistent data under repository root ./data
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(ROOT_DIR, "data")
os.makedirs(DB_DIR, exist_ok=True)

# One-time migration: if legacy backend/data/analysis.db exists, copy to ./data/analysis.db
LEGACY_DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
legacy_db_path = os.path.join(LEGACY_DB_DIR, "analysis.db")
db_path = os.path.join(DB_DIR, "analysis.db")
if not os.path.exists(db_path) and os.path.exists(legacy_db_path):
    os.makedirs(DB_DIR, exist_ok=True)
    try:
        shutil.copy2(legacy_db_path, db_path)
    except Exception:
        # If copy fails, we'll just create a fresh DB file.
        pass

SQLALCHEMY_DATABASE_URL = f"sqlite:///{db_path}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
