"""Shared task status constants.

Refactor note: the status vocabulary was previously duplicated as magic strings
across endpoints.py, worker.py, and models/task.py. Centralizing here ensures
a single source of truth.
"""

STATUS_PENDING = "pending"
STATUS_PROCESSING = "processing"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"

# Statuses that indicate an existing task is active or done (used for dedup).
ACTIVE_STATUSES = (STATUS_COMPLETED, STATUS_PENDING, STATUS_PROCESSING)

# Statuses that indicate a task was interrupted and should be requeued on startup.
UNFINISHED_STATUSES = (STATUS_PENDING, STATUS_PROCESSING)
