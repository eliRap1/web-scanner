import threading
import time
from scanner.engine import WebScanner
from scanner.task_queue import (
    job_queue,
    set_job_result,
    set_job_status,
    set_job_progress,
    increment_attempt,
    can_retry,
    MAX_RETRIES,
    set_job_failure,
)

MAX_CONCURRENT_SCANS = 2  # Limits how many browsers run at once

# Retry/backoff configuration (Feature 4.4)
# Base delay in seconds before re-queueing a failed job.
RETRY_BACKOFF_BASE = 3

def process_jobs():
    """
    Infinite loop that runs in a separate thread.
    Waits for a job, runs it, waits for the next one.
    """
    print("[*] Worker Thread Started. Waiting for jobs...")
    
    while True:
        # 1. Wait for a job (blocks until one arrives)
        job = job_queue.get()
        job_id = job['id']
        db_scan_id = job['db_scan_id'] # NEW: Extract Integer ID
        print(f"[*] Worker picked up job: {job_id}")

        # Track attempt counter (Feature 4.4)
        attempt = increment_attempt(job_id)
        set_job_progress(job_id, {
            "status": "running",
            "attempt": attempt,
            "max_retries": MAX_RETRIES,
        })
        
        # 2. Mark as "running"
        set_job_status(job_id, "running")
        
        try:
            # 3. Define the Callback
            # This function will be called BY WebScanner to update progress
            def update_progress(j_id, data):
                set_job_progress(j_id, data)
            
            # 4. Run Scanner (passing job_id and callback)
            scanner = WebScanner(
                url=job['url'],
                max_pages=job['max_pages'],
                cookies=job['cookies'],
                job_id=job_id,      # Pass ID
                db_scan_id=db_scan_id,  
                callback=update_progress  # Pass updater
            )
            
            # This is the heavy part (Playwright + Network)
            results = scanner.scan()
            
            # 5. Save Result
            set_job_result(job_id, results)
            print(f"[+] Job {job_id} completed successfully.")
            
        except Exception as e:
            err = str(e)
            print(f"[-] Job {job_id} failed (attempt {attempt}): {err}")

            # If we still have retries left, re-queue with exponential backoff
            if can_retry(job_id):
                delay = RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
                set_job_status(job_id, "pending")
                set_job_progress(job_id, {
                    "status": "pending",
                    "last_error": err,
                    "next_retry_in_seconds": delay,
                    "attempt": attempt,
                    "max_retries": MAX_RETRIES,
                })

                def _requeue():
                    job_queue.put(job)

                threading.Timer(delay, _requeue).start()
                print(f"[*] Re-queued job {job_id} in {delay}s (attempt {attempt} / max extra retries {MAX_RETRIES})")
            else:
                # Final failure
                set_job_failure(job_id, err)
        
        # 6. Task done (allows queue.Queue to know we finished)
        job_queue.task_done()

def start_worker():
    """
    Starts the worker loop in a background daemon thread.
    """
    t = threading.Thread(target=process_jobs, daemon=True)
    t.start()