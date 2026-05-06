"""
scanner/task_queue.py

Centralized job queue management with worker logic.
This is the SINGLE SOURCE OF TRUTH for process_jobs() and start_worker().
The worker.py file re-exports from here for backward compatibility.
"""

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
JOB_TIMEOUT_SECONDS = 600          # 10 minutes - vulnerability testing can take a while
WATCHDOG_INTERVAL_SECONDS = 10     # how often to check running jobs

# Global Map to link UUID -> Integer Database ID.
# Old entries are pruned by `_prune_finished_jobs` once a job's status is
# completed/failed and a TTL passes — keeps in-memory state bounded.
uuid_to_db_id = {}

# Per-job cancel events. Watchdog flips the event when a job exceeds its timeout
# so the scanner thread can wind down cooperatively (close the browser, etc.).
job_cancel_events: dict[str, threading.Event] = {}

# How long to keep finished jobs in memory before pruning their bookkeeping.
JOB_RETAIN_SECONDS = 3600  # 1 hour
_finished_at: dict[str, float] = {}


def _prune_finished_jobs():
    """Drop in-memory state for jobs that finished more than JOB_RETAIN_SECONDS ago."""
    cutoff = time.time() - JOB_RETAIN_SECONDS
    with job_lock:
        stale = [j for j, t in _finished_at.items() if t < cutoff]
        for j in stale:
            _finished_at.pop(j, None)
            job_status.pop(j, None)
            job_results.pop(j, None)
            job_progress.pop(j, None)
            job_attempts.pop(j, None)
            uuid_to_db_id.pop(j, None)
            job_cancel_events.pop(j, None)
        if stale:
            logger.info(f"Pruned in-memory state for {len(stale)} finished job(s)")


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

    Flipping the cancel event first lets the scanner thread close its Playwright
    browser and tear down workers cleanly; we only mark the job failed in the
    DB after the cooperative cancel signal has been raised.
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
            evt = job_cancel_events.get(job_id)
            if evt is not None:
                evt.set()
            set_job_failure(job_id, f"Timeout: scan exceeded {JOB_TIMEOUT_SECONDS} seconds")

        _prune_finished_jobs()
        time.sleep(WATCHDOG_INTERVAL_SECONDS)


def add_job(url: str, max_pages: int, cookies=None, user_id: int = None, proxy: str = None, enable_graph_analysis: bool = False) -> str:
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
            "proxy": proxy,  # Proxy support for Burp/ZAP
            "enable_graph_analysis": enable_graph_analysis,
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
    Saves result, updates status, marks end_time, saves vulnerabilities, and generates report.
    """
    db_scan_id = uuid_to_db_id.get(job_uuid)

    with job_lock:
        job_results[job_uuid] = result
        job_status[job_uuid] = "completed"
        if job_uuid in job_progress:
            job_progress[job_uuid]["status"] = "completed"
            job_progress[job_uuid]["result"] = result  # Include result in progress for frontend
            now = time.time()
            job_progress[job_uuid]["end_time"] = now
            st = job_progress[job_uuid].get("start_time")
            job_progress[job_uuid]["duration_seconds"] = round(now - st, 2) if st else None

    if db_scan_id:
        conn = get_connection()
        try:
            # Save vulnerabilities to database first
            findings = result.get("findings", []) if isinstance(result, dict) else []
            findings_count = 0

            if findings:
                from db.database import insert_vulnerability
                for finding in findings:
                    try:
                        # Handle both dict and object formats
                        if isinstance(finding, dict):
                            vuln_type = finding.get("type") or finding.get("vuln_type", "Unknown")
                            url = finding.get("url", "")
                            parameter = finding.get("parameter", "")
                            payload = finding.get("payload", "")
                            severity = finding.get("severity", "medium").lower()
                            confidence = finding.get("confidence", 0.8)
                        else:
                            vuln_type = getattr(finding, "vuln_type", "Unknown")
                            url = getattr(finding, "url", "")
                            parameter = getattr(finding, "parameter", "")
                            payload = getattr(finding, "payload", "")
                            severity = getattr(finding, "severity", "medium").lower()
                            confidence = getattr(finding, "confidence", 0.8)

                        insert_vulnerability(
                            conn, db_scan_id, url, parameter,
                            vuln_type, payload, severity, confidence
                        )
                        findings_count += 1
                    except Exception as ve:
                        logger.warning(f"Failed to save vulnerability: {ve}")

                logger.info(f"Saved {findings_count} vulnerabilities for scan {db_scan_id}")

            # Mark scan completed with findings count
            c = conn.cursor()
            c.execute(
                "UPDATE Scans SET status = 'completed', end_time = CURRENT_TIMESTAMP, findings_count = ? WHERE scan_id = ?",
                (findings_count, db_scan_id)
            )
            conn.commit()

            # Generate report record
            from db.database import create_report
            report_id = create_report(conn, db_scan_id)
            logger.info(f"Job {job_uuid} completed. {findings_count} vulnerabilities saved. Report {report_id} generated.")
        except Exception as e:
            logger.error(f"Failed to save results for {job_uuid}: {e}")
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


# --- Worker Logic (SINGLE DEFINITION - NO DUPLICATES) ---

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

            # Build scanner (import here to avoid circular imports)
            from scanner.engine import WebScanner
            cancel_event = threading.Event()
            with job_lock:
                job_cancel_events[job_uuid] = cancel_event
            scanner = WebScanner(
                url=job["url"],
                max_pages=job["max_pages"],
                cookies=job["cookies"],
                proxy=job.get("proxy"),  # Proxy for Burp/ZAP integration
                db_scan_id=db_scan_id,
                job_id=job_uuid,
                callback=update_progress,
                cancel_event=cancel_event,
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
                    result_data = scan_result["data"]

                    # Run graph analysis if enabled
                    if job.get("enable_graph_analysis") and isinstance(result_data, dict):
                        try:
                            from scanner.graph_analyzer import VulnerabilityGraph
                            graph = VulnerabilityGraph()
                            crawl_graph = result_data.get("crawl_graph", {})
                            graph.build_from_crawl_data(
                                visited_urls=crawl_graph.get("visited_urls", []),
                                page_links={k: set(v) for k, v in crawl_graph.get("page_links", {}).items()},
                                page_depths=crawl_graph.get("page_depths", {}),
                                page_parents=crawl_graph.get("page_parents", {}),
                                findings=result_data.get("findings", []),
                            )
                            diagram_data = graph.generate_diagram_data()
                            result_data["graph_analysis"] = diagram_data

                            # Persist to DB
                            import json as _json
                            conn = get_connection()
                            try:
                                from db.database import save_graph_data
                                save_graph_data(conn, db_scan_id, _json.dumps(diagram_data))
                            finally:
                                conn.close()

                            logger.info(f"Graph analysis completed for job {job_uuid}: "
                                        f"{diagram_data['summary']['total_nodes']} nodes, "
                                        f"{diagram_data['summary']['total_cycles']} cycles")
                        except Exception as e:
                            logger.warning(f"Graph analysis failed for job {job_uuid}: {e}")

                    set_job_result(job_uuid, result_data)
                    logger.info(f"Job {job_uuid} completed successfully.")
                else:
                    set_job_failure(job_uuid, scan_result["error"] or "Unknown scan error")

        except Exception as e:
            logger.exception(f"Job {job_uuid} failed.")
            set_job_failure(job_uuid, str(e))

        finally:
            # Mark the job for retention-window pruning. Cancel event is dropped
            # immediately because watchdog will skip jobs that aren't running.
            with job_lock:
                _finished_at[job_uuid] = time.time()
                job_cancel_events.pop(job_uuid, None)

        job_queue.task_done()


def start_worker():
    """
    Starts the worker loop in a background daemon thread.
    Feature 4.7: also starts watchdog.
    """
    t = threading.Thread(target=process_jobs, daemon=True)
    t.start()
    logger.info("Worker thread started.")

    w = threading.Thread(target=watchdog_loop, daemon=True)
    w.start()
    logger.info("Watchdog thread started.")