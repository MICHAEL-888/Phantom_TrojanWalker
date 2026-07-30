"""SQLAlchemy engine/session for SQLite.

Refactor note: added WAL mode + busy_timeout to reduce "database is locked"
errors under concurrent access from the async worker + API threadpool. Legacy
DB migration failures are now logged instead of silently swallowed.
"""
import logging
import os
import shutil

from sqlalchemy import create_engine, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

logger = logging.getLogger(__name__)

# Store all persistent data under repository root ./data
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(ROOT_DIR, "data")
os.makedirs(DB_DIR, exist_ok=True)

DB_FILENAME = "analysis.db"
DB_PATH = os.path.join(DB_DIR, DB_FILENAME)


def _legacy_db_path() -> str:
    """Resolve legacy DB path from backend/data/analysis.db."""
    legacy_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    return os.path.join(legacy_dir, DB_FILENAME)


def _migrate_legacy_db_if_needed() -> None:
    """One-time migration of legacy DB into the shared data directory.

    Refactor note: isolate migration side effects for readability. Failures
    are now logged so a migration issue is visible rather than silently
    resulting in a fresh empty DB.
    """
    legacy_path = _legacy_db_path()
    if os.path.exists(DB_PATH) or not os.path.exists(legacy_path):
        return

    os.makedirs(DB_DIR, exist_ok=True)
    try:
        shutil.copy2(legacy_path, DB_PATH)
        logger.info("Migrated legacy DB from %s to %s", legacy_path, DB_PATH)
    except Exception as exc:
        logger.warning("Legacy DB migration failed (%s); will create fresh DB.", exc)


_migrate_legacy_db_if_needed()

SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    # Refactor note: 5-second busy timeout lets concurrent writers wait briefly
    # instead of immediately raising "database is locked".
    pool_pre_ping=True,
)


@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    """Enable WAL mode + busy timeout on every new SQLite connection.

    Refactor note: WAL allows concurrent readers alongside a single writer,
    which fits the pattern of the API threadpool reading while the worker writes.
    """
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA synchronous=NORMAL")
    finally:
        cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency that yields a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
