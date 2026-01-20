import logging
import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Ensure project root + agents are importable when running this file directly.
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
AGENTS_DIR = os.path.join(ROOT_DIR, "agents")
if AGENTS_DIR not in sys.path:
    sys.path.insert(0, AGENTS_DIR)

if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    # Optional in some environments
    pass

from backend.database import engine, Base
from backend.api import endpoints
from backend.worker.worker import worker

# Create tables
Base.metadata.create_all(bind=engine)

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
    lifespan=lifespan
)

# CORS
origins = [
    "http://localhost:5173", # Vite default
    "http://localhost:3000",
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
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
