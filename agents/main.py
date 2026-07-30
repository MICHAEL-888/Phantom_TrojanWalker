"""Legacy FastAPI entrypoint for the agents layer.

Refactor note: prefer backend/main.py (v2) which exposes /api/* and drives
the coordinator via the worker. This file is kept for standalone development.
Agents now receive AppConfig via DI; bare imports are wrapped in try/except
so the module works both as a package (from agents.main import app) and as
a script (python agents/main.py).
"""
import logging
import os
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import JSONResponse
from colorama import Fore, Style, init
from dotenv import load_dotenv

try:
    from .config_loader import load_config
    from .agent_core import FunctionAnalysisAgent, MalwareAnalysisAgent
    from .ghidra_client import GhidraClient
    from .analysis_coordinator import AnalysisCoordinator
    from .exceptions import TrojanWalkerError
except ImportError:  # script-mode execution (python agents/main.py)
    from config_loader import load_config
    from agent_core import FunctionAnalysisAgent, MalwareAnalysisAgent
    from ghidra_client import GhidraClient
    from analysis_coordinator import AnalysisCoordinator
    from exceptions import TrojanWalkerError


load_dotenv()
init(autoreset=True)


class ColoredFormatter(logging.Formatter):
    """彩色日志格式化器。"""

    _LEVEL_COLORS = {
        logging.DEBUG: Fore.BLUE,
        logging.INFO: Fore.CYAN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def format(self, record):
        color = self._LEVEL_COLORS.get(record.levelno, Fore.WHITE)

        timestamp = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
        asctime = f"{Fore.GREEN}{timestamp}{Style.RESET_ALL}"
        level = f"{color}{record.levelname:<8}{Style.RESET_ALL}"
        msg = (
            f"{Style.BRIGHT}{record.msg}{Style.RESET_ALL}"
            if record.levelno == logging.INFO
            else record.msg
        )

        return f"{asctime} - {level} - {msg}"


def configure_logging() -> logging.Logger:
    """初始化日志配置并返回模块 logger。"""
    handler = logging.StreamHandler()
    handler.setFormatter(ColoredFormatter())

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    if not any(isinstance(h, logging.StreamHandler) for h in root_logger.handlers):
        root_logger.addHandler(handler)

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    return logging.getLogger(__name__)


def build_coordinator(logger: logging.Logger) -> Optional[AnalysisCoordinator]:
    """初始化并构建核心服务对象。

    Refactor note: agents now receive AppConfig via DI instead of calling
    load_config() internally, so config.yaml is loaded once here.
    """
    try:
        logger.info("Initializing services...")
        config = load_config()

        ghidra_client = GhidraClient(config)
        function_agent = FunctionAnalysisAgent(config=config)
        malware_agent = MalwareAnalysisAgent(config=config)

        coordinator = AnalysisCoordinator(ghidra_client, function_agent, malware_agent)
        logger.info("Services initialized successfully.")
        return coordinator
    except Exception as exc:
        logger.critical(f"Failed to initialize services: {exc}")
        return None


def create_app() -> FastAPI:
    """创建 FastAPI 应用并注册路由/异常处理器。"""
    app = FastAPI()
    logger = configure_logging()
    coordinator = build_coordinator(logger)

    @app.exception_handler(TrojanWalkerError)
    async def trojan_walker_exception_handler(request: Request, exc: TrojanWalkerError):
        logger.error(f"Known Application Error: {str(exc)}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "type": type(exc).__name__,
                "message": str(exc),
            },
        )

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled Exception: {str(exc)}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "type": "InternalServerError",
                "message": "An unexpected error occurred.",
            },
        )

    @app.post("/analyze")
    async def analyze_endpoint(file: UploadFile = File(...)):
        if coordinator is None:
            raise TrojanWalkerError("Service not initialized properly.")
        return await coordinator.analyze_file(file)

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    # Legacy entrypoint (v1). Prefer running backend/main.py (v2) on :8001.
    port = int(os.getenv("AGENTS_PORT", "8002"))
    uvicorn.run(app, host="0.0.0.0", port=port)
