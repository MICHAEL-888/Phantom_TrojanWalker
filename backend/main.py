import logging
import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text


def _ensure_import_paths() -> None:
    """Ensure project root + agents are importable when running directly.

    Refactor note: centralize path tweaks to keep module init concise.
    """
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root_dir not in sys.path:
        sys.path.insert(0, root_dir)
    agents_dir = os.path.join(root_dir, "agents")
    if agents_dir not in sys.path:
        sys.path.insert(0, agents_dir)


def _configure_logging() -> None:
    """Configure default logging when no handlers exist."""
    if logging.getLogger().handlers:
        return
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def _load_env() -> None:
    """Load dotenv if available (optional for some environments)."""
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except Exception:
        pass


def _resolve_cors_origins() -> list[str]:
    """Resolve CORS origins list from env with safe defaults."""
    origins_env = os.getenv("PTW_CORS_ORIGINS")
    if origins_env:
        return [o.strip() for o in origins_env.split(",") if o.strip()]
    return [
        "http://localhost:5173",  # Vite default
        "http://localhost:3000",
        "http://localhost:8080",  # frontend server.mjs
    ]


_ensure_import_paths()
_configure_logging()
_load_env()

from backend.database import engine, Base
from backend.api import endpoints
from backend.worker.worker import worker


def _ensure_runtime_indexes() -> None:
    """Create performance-critical indexes for existing SQLite deployments."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_analysis_tasks_created_at_desc "
                "ON analysis_tasks (created_at DESC)"
            )
        )

# Create tables
Base.metadata.create_all(bind=engine)
_ensure_runtime_indexes()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await worker.start()
    yield
    # Shutdown
    # We could stop worker here if needed


app = FastAPI(
    title="Phantom TrojanWalker API",
    description="Backend for Malware Analysis Framework",
    version="2.0",
    lifespan=lifespan,
)

# CORS
# IMPORTANT: When allow_credentials=True, allow_origins cannot include "*".
app.add_middleware(
    CORSMiddleware,
    allow_origins=_resolve_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(endpoints.router, prefix="/api")


@app.get("/")
def read_root():
    return {"message": "Phantom TrojanWalker API is ready."}


def main() -> None:
    import uvicorn

    host = os.getenv("BACKEND_HOST", "0.0.0.0")
    port = int(os.getenv("BACKEND_PORT", "8001"))
    reload_env = os.getenv("BACKEND_RELOAD", "1")
    reload_enabled = reload_env.lower() in {"1", "true", "yes", "y"}

    # Using import string keeps reload working.
    uvicorn.run("backend.main:app", host=host, port=port, reload=reload_enabled)


if __name__ == "__main__":
    main()
