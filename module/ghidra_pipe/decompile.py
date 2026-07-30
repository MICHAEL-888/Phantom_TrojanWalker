"""Decompilation service.

Refactor note: extracted from GhidraAnalyzer and the duplicated decompile logic
between single and batch is unified into `_decompile_one`. The single-endpoint
return shape now includes `address` for consistency with the batch endpoint.
"""
import logging
from typing import Any, Dict, List, Optional

try:
    from . import _jvm
    from .addressing import find_function
except ImportError:  # script-mode execution (python module/ghidra_pipe/main.py)
    import _jvm
    from addressing import find_function

logger = logging.getLogger(__name__)

_DECOMPILE_TIMEOUT_SECONDS = 60


def _decompile_one(decompiler: Any, func: Any, monitor: Any) -> Optional[str]:
    """Decompile a single function; return C source or None."""
    try:
        results = decompiler.decompileFunction(func, _DECOMPILE_TIMEOUT_SECONDS, monitor)
        if results and results.decompileCompleted():
            decomp_func = results.getDecompiledFunction()
            if decomp_func:
                code = decomp_func.getC()
                if code:
                    return code
    except Exception as e:
        logger.warning(f"Error decompiling function: {e}")
    return None


def decompile_one(program: Any, decompiler: Any, address_or_name: str) -> Optional[Dict[str, str]]:
    """Decompile a single function by name or address.

    Returns {"address": ..., "code": ...} or None. Refactor note: include
    `address` to align the shape with the batch endpoint.
    """
    if program is None or decompiler is None:
        return None
    try:
        func = find_function(program, address_or_name)
        if not func:
            return None
        monitor = _jvm.get_console_task_monitor_cls()()
        code = _decompile_one(decompiler, func, monitor)
        if code is None:
            return None
        return {"address": address_or_name, "code": code}
    except Exception as e:
        logger.error(f"Error decompiling {address_or_name}: {e}")
        return None


def decompile_batch(program: Any, decompiler: Any, addresses: List[str]) -> List[Dict[str, str]]:
    """Batch decompile; failed items are skipped (missing-item semantics)."""
    if program is None or decompiler is None:
        return []

    results: List[Dict[str, str]] = []
    monitor = _jvm.get_console_task_monitor_cls()()

    for addr in addresses:
        try:
            func = find_function(program, addr)
            if not func:
                continue
            code = _decompile_one(decompiler, func, monitor)
            if code:
                results.append({"address": addr, "code": code})
        except Exception as e:
            logger.warning(f"Error decompiling {addr}: {e}")
            continue

    logger.info(f"Decompiled {len(results)}/{len(addresses)} functions")
    return results
