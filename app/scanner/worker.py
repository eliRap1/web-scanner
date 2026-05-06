"""
scanner/worker.py

Re-exports from task_queue.py for backward compatibility.
The actual worker logic lives in scanner/task_queue.py (single source of truth).
"""

from scanner.task_queue import (
    start_worker,
    process_jobs,
    job_queue,
    set_job_result,
    set_job_status,
    set_job_progress,
    increment_attempt,
    can_retry,
    MAX_RETRIES,
    set_job_failure,
)
