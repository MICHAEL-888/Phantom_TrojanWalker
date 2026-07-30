"""Langfuse tracing and debug logging helpers.

Refactor note: extracted from agent_core to isolate observability concerns
(Langfuse callback creation, debug packet logging) from agent logic.
"""
import json
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEBUG_LOGGER_NAME = "phantom.malware_debug"
DEBUG_ENV_KEY = "PHANTOM_DEBUG"
LANGFUSE_REQUIRED_ENV_KEYS = (
    "LANGFUSE_SECRET_KEY",
    "LANGFUSE_PUBLIC_KEY",
    "LANGFUSE_BASE_URL",
)


def is_phantom_debug_enabled() -> bool:
    value = os.getenv(DEBUG_ENV_KEY, "")
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _resolve_debug_log_path() -> str:
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(project_root, "data", "logs", "malware_agent_debug.log")


def _json_default_serializer(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "dict"):
        return value.dict()
    if isinstance(value, set):
        return list(value)
    if hasattr(value, "__dict__"):
        return vars(value)
    return str(value)


def to_pretty_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, indent=2, default=_json_default_serializer)
    except Exception:
        return str(value)


def get_debug_logger() -> logging.Logger:
    debug_logger = logging.getLogger(DEBUG_LOGGER_NAME)
    if debug_logger.handlers:
        return debug_logger

    debug_log_path = _resolve_debug_log_path()
    os.makedirs(os.path.dirname(debug_log_path), exist_ok=True)
    handler = logging.FileHandler(debug_log_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    debug_logger.addHandler(handler)
    debug_logger.setLevel(logging.INFO)
    debug_logger.propagate = False
    return debug_logger


def create_langfuse_callback_handler() -> Optional[Any]:
    """Create a Langfuse callback handler if all required envs are set."""
    missing = [k for k in LANGFUSE_REQUIRED_ENV_KEYS if not os.getenv(k, "").strip()]
    if missing:
        logger.info("Langfuse tracing disabled: missing envs: %s", ", ".join(missing))
        return None

    callback_cls = None
    try:
        from langfuse.langchain import CallbackHandler as LangfuseCallbackHandler
        callback_cls = LangfuseCallbackHandler
    except Exception:
        try:
            from langfuse.callback import CallbackHandler as LangfuseCallbackHandler
            callback_cls = LangfuseCallbackHandler
        except Exception as exc:
            logger.warning("Langfuse callback import failed: %s", exc)
            return None

    try:
        handler = callback_cls()
    except Exception as exc:
        logger.warning("Langfuse callback initialization failed: %s", exc)
        return None

    logger.info("Langfuse tracing enabled for agent calls.")
    return handler


def build_invoke_config(
    callback_handler: Optional[Any],
    run_name: str,
    tags: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    if not callback_handler:
        return None

    config: Dict[str, Any] = {
        "callbacks": [callback_handler],
        "run_name": run_name,
    }
    if tags:
        config["tags"] = tags
    return config
