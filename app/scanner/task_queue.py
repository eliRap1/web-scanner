import queue
import uuid
import threading
import logging
import time
from db.database import get_connection

logger = logging.getLogger(__name__)

# --- Queue Management ---
job_queue = queue.Queue()

# --- Shared State (Thread Safe) ---
job_lock = threading.Lock()

# Status: 'pending', 'running', 'completed', 'failed'
job_status = {}

# Results: Final scan target list / error dict
job_results = {}

# Progress: Real-time data (current_url, visited_count, targets_so_far, timing)
job_progress = {}

# Attempts: retry counters per job (Feature 4.4)
job_attempts = {}

# Retry configuration (Feature 4.4)
# MAX_RETRIES = number of *additional* tries after the first attempt.
MAX_RETRIES = 2

# Feature 4.7: resilience configuration
JOB_TIMEOUT_SECONDS = 120          # hard timeout for a scan attempt
WATCHDOG_INTERVAL_SECONDS = 5      # how often to check running jobs

# Global Map to link UUID -> Integer Database ID
uuid_to_db_id = {}


def recover_stuck_scans_on_startup():
    """
    Feature 4.7: If the server restarted while scans were running,
    mark them as failed in DB to keep consistency.
    """
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute(
            """
            UPDATE Scans
            SET status='failed', end_time=CURRENT_TIMESTAMP
            WHERE status='running'
            """
        )
        conn.commit()
        logger.info("Recovery: marked stuck 'running' scans as failed in DB (if any).")
    except Exception:
        conn.rollback()
        logger.exception("Recovery: failed to update stuck scans.")
    finally:
        conn.close()


def watchdog_loop():
    """
    Feature 4.7: Watchdog that fails jobs stuck in 'running' for too long.
    """
    logger.info("Watchdog started.")
    while True:
        now = time.time()
        to_fail = []

        with job_lock:
            for job_id, prog in job_progress.items():
                if prog.get("status") == "running":
                    st = prog.get("start_time")
                    if st and (now - st) > JOB_TIMEOUT_SECONDS:
                        to_fail.append(job_id)

        for job_id in to_fail:
            set_job_failure(job_id, f"Timeout: scan exceeded {JOB_TIMEOUT_SECONDS} seconds")
    
        time.sleep(WATCHDOG_INTERVAL_SECONDS)


def add_job(url: str, max_pages: int, cookies=None, user_id: int = None) -> str:
    """
    Adds a job to the queue AND creates a persistent record in the database.
    Feature 4.5: stores queued_at, and start_time/end_time are tracked properly.
    """
    job_uuid = str(uuid.uuid4())

    conn = get_connection()
    try:
        c = conn.cursor()
        # Feature 4.5: start_time should be NULL until the worker starts.
        c.execute(
            "INSERT INTO Scans (user_id, target_url, status, start_time) VALUES (?, ?, 'pending', NULL)",
            (user_id, url)
        )
        conn.commit()

        db_scan_id = c.lastrowid
        logger.info(f"Created DB record for Job {job_uuid} -> scan_id: {db_scan_id}")

        with job_lock:
            uuid_to_db_id[job_uuid] = db_scan_id

        queued_at = time.time()
        job_data = {
            "id": job_uuid,
            "db_scan_id": db_scan_id,
            "url": url,
            "max_pages": max_pages,
            "cookies": cookies,
            # Feature 4.5 timing
            "queued_at": queued_at,
            "start_time": None,
            "end_time": None,
            "duration_seconds": None
        }

        with job_lock:
            job_queue.put(job_data)
            job_status[job_uuid] = "pending"
            job_attempts[job_uuid] = 0

            job_progress[job_uuid] = {
                "current_url": "",
                "visited_count": 0,
                "found_count": 0,
                "status": "pending",
                "attempt": 0,
                "max_retries": MAX_RETRIES,
                "last_error": "",
                "targets_so_far": [],
                # Feature 4.5 timing fields (epoch seconds)
                "queued_at": queued_at,
                "start_time": None,
                "end_time": None,
                "duration_seconds": None
            }

    except Exception as e:
        logger.error(f"Failed to insert job into DB: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()

    return job_uuid


# --- Read/Update Functions ---

def get_job_status(job_uuid: str):
    with job_lock:
        return job_status.get(job_uuid)


def set_job_status(job_uuid: str, status: str):
    """
    Updates both in-memory status and Database status.
    Feature 4.5: when status becomes 'running' set start_time in progress + DB.
    """
    db_scan_id = uuid_to_db_id.get(job_uuid)

    with job_lock:
        job_status[job_uuid] = status
        if job_uuid in job_progress:
            job_progress[job_uuid]["status"] = status

            if status == "running" and job_progress[job_uuid].get("start_time") is None:
                job_progress[job_uuid]["start_time"] = time.time()
                job_progress[job_uuid]["duration_seconds"] = None

    if db_scan_id:
        conn = get_connection()
        try:
            c = conn.cursor()
            if status == "running":
                c.execute(
                    "UPDATE Scans SET status = ?, start_time = CURRENT_TIMESTAMP WHERE scan_id = ?",
                    (status, db_scan_id)
                )
            else:
                c.execute(
                    "UPDATE Scans SET status = ? WHERE scan_id = ?",
                    (status, db_scan_id)
                )
            conn.commit()
            logger.info(f"Updated DB Job {job_uuid} (ID: {db_scan_id}) status to {status}")
        except Exception as e:
            logger.error(f"Failed to update DB status for {job_uuid}: {e}")
            conn.rollback()
        finally:
            conn.close()


def get_job_result(job_uuid: str):
    with job_lock:
        return job_results.get(job_uuid)


def set_job_result(job_uuid: str, result):
    """
    Saves result, updates status, marks end_time, and generates report.
    """
    db_scan_id = uuid_to_db_id.get(job_uuid)

    with job_lock:
        job_results[job_uuid] = result
        job_status[job_uuid] = "completed"
        if job_uuid in job_progress:
            job_progress[job_uuid]["status"] = "completed"
            now = time.time()
            job_progress[job_uuid]["end_time"] = now
            st = job_progress[job_uuid].get("start_time")
            job_progress[job_uuid]["duration_seconds"] = round(now - st, 2) if st else None

    if db_scan_id:
        conn = get_connection()
        try:
            # Mark scan completed
            c = conn.cursor()
            c.execute(
                "UPDATE Scans SET status = 'completed', end_time = CURRENT_TIMESTAMP WHERE scan_id = ?",
                (db_scan_id,)
            )
            conn.commit()
            
            # Generate report!
            from db.database import create_report
            report_id = create_report(conn, db_scan_id)
            logger.info(f"Job {job_uuid} completed. Report {report_id} generated.")
        except Exception as e:
            logger.error(f"Failed to generate report for {job_uuid}: {e}")
            conn.rollback()
        finally:
            conn.close()


def set_job_progress(job_uuid: str, data: dict):
    """
    Updates progress dictionary.
    Data can be counts OR a new_target.
    """
    with job_lock:
        if job_uuid in job_progress:
            job_progress[job_uuid].update(data)

            if "new_target" in data:
                job_progress[job_uuid]["targets_so_far"].append(data["new_target"])
                job_progress[job_uuid]["found_count"] = len(job_progress[job_uuid]["targets_so_far"])
        else:
            job_progress[job_uuid] = data


def get_job_progress(job_uuid: str):
    with job_lock:
        return job_progress.get(job_uuid)


# --- Retry helpers (Feature 4.4) ---

def increment_attempt(job_uuid: str) -> int:
    """Increment and return the current attempt number (1-based for display)."""
    with job_lock:
        prev = job_attempts.get(job_uuid, 0)
        job_attempts[job_uuid] = prev + 1
        if job_uuid in job_progress:
            job_progress[job_uuid]["attempt"] = job_attempts[job_uuid]
        return job_attempts[job_uuid]


def get_attempt(job_uuid: str) -> int:
    with job_lock:
        return job_attempts.get(job_uuid, 0)


def can_retry(job_uuid: str) -> bool:
    """True if we still have retries left (MAX_RETRIES additional tries)."""
    return get_attempt(job_uuid) < (1 + MAX_RETRIES)


def set_job_failure(job_uuid: str, error_message: str):
    """
    Mark job failed (in-memory + DB) and store error result.
    Feature 4.5: compute end_time + duration for failed jobs too.
    """
    with job_lock:
        job_results[job_uuid] = {"error": error_message}
        job_status[job_uuid] = "failed"
        if job_uuid in job_progress:
            job_progress[job_uuid]["status"] = "failed"
            job_progress[job_uuid]["last_error"] = error_message

            now = time.time()
            job_progress[job_uuid]["end_time"] = now
            st = job_progress[job_uuid].get("start_time")
            job_progress[job_uuid]["duration_seconds"] = round(now - st, 2) if st else None

    db_scan_id = uuid_to_db_id.get(job_uuid)
    if db_scan_id:
        conn = get_connection()
        try:
            c = conn.cursor()
            c.execute(
                "UPDATE Scans SET status = 'failed', end_time = CURRENT_TIMESTAMP WHERE scan_id = ?",
                (db_scan_id,)
            )
            conn.commit()
        except Exception:
            conn.rollback()
            logger.exception("Failed to mark job failed in DB")
        finally:
            conn.close()


# --- Worker Logic ---

def process_jobs():
    """
    Infinite loop that runs in a separate thread.
    Waits for a job, runs it, waits for the next one.
    Feature 4.7: per-job timeout wrapper.
    """
    logger.info("Worker thread started. Waiting for jobs...")

    while True:
        job = job_queue.get()
        job_uuid = job["id"]
        db_scan_id = job["db_scan_id"]

        logger.info(f"Worker picked up job: {job_uuid} (DB ID: {db_scan_id})")

        # Feature 4.4 attempt count
        increment_attempt(job_uuid)

        # Mark running (sets start_time)
        set_job_status(job_uuid, "running")

        try:
            def update_progress(uuid_, data):
                set_job_progress(uuid_, data)

            # Build scanner
            from scanner.engine import WebScanner
            scanner = WebScanner(
                url=job["url"],
                max_pages=job["max_pages"],
                cookies=job["cookies"],
                db_scan_id=db_scan_id,
                job_id=job_uuid,
                callback=update_progress
            )

            # --- Feature 4.7: enforce timeout around scan() ---
            scan_result = {"ok": False, "data": None, "error": None}

            def run_scan():
                try:
                    scan_result["data"] = scanner.scan()
                    scan_result["ok"] = True
                except Exception as e:
                    scan_result["error"] = str(e)

            scan_thread = threading.Thread(target=run_scan, daemon=True)
            scan_thread.start()
            scan_thread.join(timeout=JOB_TIMEOUT_SECONDS)

            if scan_thread.is_alive():
                # Timed out
                set_job_failure(job_uuid, f"Timeout: scan exceeded {JOB_TIMEOUT_SECONDS} seconds")
            else:
                if scan_result["ok"]:
                    set_job_result(job_uuid, scan_result["data"])
                    logger.info(f"Job {job_uuid} completed successfully.")
                else:
                    set_job_failure(job_uuid, scan_result["error"] or "Unknown scan error")

        except Exception as e:
            logger.exception(f"Job {job_uuid} failed.")
            set_job_failure(job_uuid, str(e))

        job_queue.task_done()


def start_worker():
    """
    Starts the worker loop in a background daemon thread.
    Feature 4.7: also starts watchdog.
    """
    t = threading.Thread(target=process_jobs, daemon=True)
    t.start()

    w = threading.Thread(target=watchdog_loop, daemon=True)
    w.start()
