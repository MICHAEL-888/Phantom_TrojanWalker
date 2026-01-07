from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

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
