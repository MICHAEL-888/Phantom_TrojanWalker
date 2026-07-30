"""File size formatting helpers.

Refactor note: extracted from GhidraAnalyzer to keep formatting concerns
isolated and reusable without carrying analyzer state.
"""
from typing import Optional

_UNITS = ("B", "KB", "MB", "GB", "TB")
_DIVISOR = 1024


def format_size(file_size: int) -> Optional[str]:
    """Format a byte count into a human-readable string."""
    try:
        size = float(file_size)
        idx = 0
        while size >= _DIVISOR and idx < len(_UNITS) - 1:
            size /= float(_DIVISOR)
            idx += 1
        return f"{size:.2f}{_UNITS[idx]}" if idx > 0 else f"{int(size)}{_UNITS[idx]}"
    except Exception:
        return None


def get_sizes(file_path: str) -> tuple[Optional[int], Optional[str]]:
    """Return (raw_size, human_readable_size) for a file path."""
    import os

    try:
        file_size = os.path.getsize(file_path)
    except Exception:
        return None, None
    return file_size, format_size(file_size)
