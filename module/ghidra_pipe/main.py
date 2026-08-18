"""Ghidra Pipe FastAPI Service.

Provides HTTP endpoints for binary analysis using Ghidra/pyghidra.
"""
import os
import uuid
import threading
import logging
import hashlib
import signal
import time
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI, UploadFile, File, HTTPException

try:
    from .analyzer import GhidraAnalyzer
except ImportError:  # script-mode execution (python module/ghidra_pipe/main.py)
    from analyzer import GhidraAnalyzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global analyzer state (single instance — Ghidra/JVM is process-global).
analyzer = None
analyzer_lock = threading.RLock()
restart_pending = False

# Upload directory resolved from repo root.
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
UPLOAD_DIR = os.path.join(ROOT_DIR, "data", "uploads")


def _ensure_upload_dir() -> None:
    """Create the upload directory on startup (not at import time)."""
    os.makedirs(UPLOAD_DIR, exist_ok=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Refactor note: move filesystem side effects out of import time into the
    # app lifespan so importing this module for testing or introspection does
    # not create directories.
    _ensure_upload_dir()
    yield


app = FastAPI(title="Ghidra Pipe Service", version="1.0.0", lifespan=lifespan)


def _safe_tmp_upload_path() -> str:
    """Create a temp upload path guarded against path traversal."""
    tmp_name = f".tmp_{uuid.uuid4().hex}"
    tmp_path = os.path.normpath(os.path.join(UPLOAD_DIR, tmp_name))
    if os.path.commonpath([UPLOAD_DIR, tmp_path]) != UPLOAD_DIR:
        raise HTTPException(status_code=400, detail="Invalid upload path")
    return tmp_path


def _resolve_final_upload_path(sha256: str) -> str:
    """Resolve final upload path by sha256 with path traversal guard."""
    file_path = os.path.normpath(os.path.join(UPLOAD_DIR, sha256))
    if os.path.commonpath([UPLOAD_DIR, file_path]) != UPLOAD_DIR:
        raise HTTPException(status_code=400, detail="Invalid filename")
    return file_path


def _remove_file_quietly(path: str) -> None:
    """Best-effort file deletion to avoid masking primary errors."""
    try:
        os.remove(path)
    except OSError:
        pass


async def _stream_to_temp_file(file: UploadFile, tmp_path: str) -> str:
    """Stream upload to temp file while computing sha256."""
    hasher = hashlib.sha256()
    with open(tmp_path, "wb") as out_file:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
            out_file.write(chunk)
    return hasher.hexdigest()


def _persist_upload(tmp_path: str, sha256: str) -> str:
    """Move temp file into final path, handling collisions safely."""
    file_path = _resolve_final_upload_path(sha256)
    try:
        if os.path.exists(file_path):
            _remove_file_quietly(tmp_path)
        else:
            os.replace(tmp_path, file_path)
    except OSError as e:
        _remove_file_quietly(tmp_path)
        raise HTTPException(status_code=500, detail=f"Failed to store upload: {e}")
    return file_path


def require_analyzer() -> GhidraAnalyzer:
    """Get the current analyzer or raise 409 if not initialized."""
    global analyzer
    if analyzer is None:
        raise HTTPException(status_code=409, detail="No binary uploaded. POST /upload first.")
    return analyzer


def _close_analyzer() -> None:
    """Close the current analyzer and clear global state."""
    global analyzer
    if analyzer is None:
        return
    try:
        analyzer.close()
    finally:
        analyzer = None


def _read_proc_memory() -> dict:
    """Read current process memory counters without adding a runtime dependency."""
    result = {}
    try:
        with open("/proc/self/status", "r", encoding="ascii") as status_file:
            for line in status_file:
                key, separator, value = line.partition(":")
                if separator and key in {"VmRSS", "VmSize", "Threads"}:
                    parts = value.strip().split()
                    if parts:
                        result[key] = int(parts[0]) * (1024 if len(parts) > 1 and parts[1] == "kB" else 1)
    except (OSError, ValueError):
        pass
    return result


def _read_cgroup_value(path: str):
    """Read a cgroup v2 value when available."""
    try:
        with open(path, "r", encoding="ascii") as value_file:
            value = value_file.read().strip()
        return value if value == "max" else int(value)
    except (OSError, ValueError):
        return None


def _memory_snapshot() -> dict:
    """Return process, cgroup, and JVM memory counters for troubleshooting."""
    snapshot = {
        "process": _read_proc_memory(),
        "cgroup": {
            "current_bytes": _read_cgroup_value("/sys/fs/cgroup/memory.current"),
            "limit_bytes": _read_cgroup_value("/sys/fs/cgroup/memory.max"),
        },
        "jvm": None,
    }

    try:
        import java.lang.management

        memory = java.lang.management.ManagementFactory.getMemoryMXBean()
        heap = memory.getHeapMemoryUsage()
        non_heap = memory.getNonHeapMemoryUsage()
        snapshot["jvm"] = {
            "heap_used_bytes": heap.getUsed(),
            "heap_committed_bytes": heap.getCommitted(),
            "heap_max_bytes": heap.getMax(),
            "non_heap_used_bytes": non_heap.getUsed(),
            "non_heap_committed_bytes": non_heap.getCommitted(),
        }
    except Exception:
        # JVM is not started before the first upload, or management access is unavailable.
        pass

    return snapshot


def _force_terminate_process(delay_seconds: float = 0.2) -> None:
    """Terminate current process to hard-stop any ongoing Ghidra work."""
    time.sleep(max(delay_seconds, 0.0))
    pid = os.getpid()
    logger.error("Force terminating ghidra_pipe process (pid=%s)", pid)
    try:
        sig = signal.SIGKILL if hasattr(signal, "SIGKILL") else signal.SIGTERM
        os.kill(pid, sig)
    except Exception:
        os._exit(1)


def _restart_after_close(delay_seconds: float = 0.2) -> None:
    """Exit after cleanup so compose replaces the JVM with a fresh process."""
    time.sleep(max(delay_seconds, 0.0))
    pid = os.getpid()
    logger.warning("Restarting ghidra_pipe after close (pid=%s)", pid)
    try:
        os.kill(pid, signal.SIGTERM)
    except Exception:
        os._exit(1)


@app.get("/health_check")
def health_check():
    """Report whether Pipe can safely accept another analysis task."""
    with analyzer_lock:
        return {"status": "restarting" if restart_pending else "ok"}


@app.get("/memory")
def memory_snapshot():
    """Expose process/cgroup/JVM memory counters for operational diagnostics."""
    return _memory_snapshot()


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    """Upload a binary for analysis; closes any previously opened analyzer."""
    global analyzer

    tmp_path = _safe_tmp_upload_path()
    sha256 = await _stream_to_temp_file(file, tmp_path)
    path = _persist_upload(tmp_path, sha256)

    with analyzer_lock:
        try:
            _close_analyzer()
        except Exception as e:
            logger.warning(f"Error closing previous analyzer: {e}")

        analyzer = GhidraAnalyzer(path)
        if not analyzer.open():
            analyzer = None
            raise HTTPException(500, "Ghidra open failed")

    return {"status": "ok"}


@app.post("/close")
def close_analyzer():
    """Explicitly release Ghidra resources for the current binary."""
    global analyzer, restart_pending
    with analyzer_lock:
        had_analyzer = analyzer is not None
        _close_analyzer()
        restart_scheduled = (
            had_analyzer
            and os.getenv("GHIDRA_RESTART_AFTER_CLOSE", "0").lower() in {"1", "true", "yes"}
        )
        if restart_scheduled:
            # Expose draining state before the delayed process termination runs.
            restart_pending = True
    if restart_scheduled:
        threading.Thread(target=_restart_after_close, daemon=True).start()
    return {"status": "closed", "restart_scheduled": restart_scheduled}


@app.post("/stop_analysis")
def stop_analysis():
    """Force-stop current analysis by terminating ghidra_pipe process."""
    global restart_pending
    logger.error("Received /stop_analysis request, scheduling forced process termination.")
    # Signal the draining state before the delayed termination starts.  This
    # prevents a recovery health check from observing a brief false "ok" and
    # letting the next sample upload while the old process is still dying.
    # Do not acquire analyzer_lock here: a timed-out synchronous endpoint may
    # still hold it while the process is being force-terminated.
    restart_pending = True
    threading.Thread(target=_force_terminate_process, daemon=True).start()
    return {"status": "accepted", "message": "Process termination scheduled"}


@app.get("/analyze")
def do_analyze():
    """Trigger Ghidra auto-analysis on the uploaded binary."""
    with analyzer_lock:
        return require_analyzer().analyze()


@app.get("/metadata")
def get_meta():
    """Get binary metadata/info."""
    with analyzer_lock:
        return require_analyzer().get_info()


@app.get("/functions")
def get_funcs():
    """Get list of functions in the binary."""
    with analyzer_lock:
        return require_analyzer().get_functions()


@app.get("/exports")
def get_exports():
    """Get export table entries from the binary."""
    with analyzer_lock:
        return require_analyzer().get_exports()


@app.get("/strings")
def get_strs():
    """Get strings from the binary."""
    with analyzer_lock:
        return require_analyzer().get_strings()


@app.get("/decompile")
def decompile(addr: str):
    """Decompile a single function by address or name."""
    with analyzer_lock:
        result = require_analyzer().get_decompiled_code(addr)
        if result is None:
            raise HTTPException(404, f"Function not found or decompilation failed: {addr}")
        return result


@app.get("/callgraph")
def get_callgraph():
    """Get global call graph."""
    with analyzer_lock:
        return require_analyzer().get_global_call_graph()


@app.post("/decompile_batch")
def decompile_batch(addresses: List[str]):
    """Batch decompile; returns list of {address, code}."""
    with analyzer_lock:
        return require_analyzer().get_decompiled_code_batch(addresses)


@app.get("/xrefs")
def get_xrefs(addr: str):
    """Get cross-references for a single function. Returns {name, offset, callers, callees}."""
    with analyzer_lock:
        result = require_analyzer().get_function_xrefs(addr)
        if result is None:
            raise HTTPException(404, f"Function not found: {addr}")
        return result


@app.post("/xrefs_batch")
def get_xrefs_batch(addresses: List[str]):
    """Batch get cross-references; returns list of {name, offset, callers, callees}."""
    with analyzer_lock:
        return require_analyzer().get_function_xrefs_batch(addresses)


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("GHIDRA_PIPE_HOST", "0.0.0.0")
    port = int(os.getenv("GHIDRA_PIPE_PORT", "8000"))
    uvicorn.run(app, host=host, port=port)
