import threading
from scanner.engine import WebScanner
from scanner.task_queue import job_queue, job_status, set_job_result, set_job_status, set_job_progress

MAX_CONCURRENT_SCANS = 2  # Limits how many browsers run at once

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
            print(f"[-] Job {job_id} failed: {e}")
            # Save error as result so user knows
            set_job_result(job_id, {"error": str(e)})
            set_job_status(job_id, "failed")
        
        # 6. Task done (allows queue.Queue to know we finished)
        job_queue.task_done()

def start_worker():
    """
    Starts the worker loop in a background daemon thread.
    """
    t = threading.Thread(target=process_jobs, daemon=True)
    t.start()