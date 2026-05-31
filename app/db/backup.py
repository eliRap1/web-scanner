import os
import shutil
import datetime
import sqlite3
import schedule
import time
import logging

DB_FILE = "web_scanner.db"
BACKUP_DIR = "db_backups"
MAX_BACKUPS = 10

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("backup_system")

# ---------------------------
# Database helper
# ---------------------------
def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

# ---------------------------
# Backup System
# ---------------------------
def ensure_backup_dir():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)

def create_backup():
    ensure_backup_dir()

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    backup_name = f"backup_{timestamp}.db"
    backup_path = os.path.join(BACKUP_DIR, backup_name)

    shutil.copy2(DB_FILE, backup_path)

    logger.info(f"[BACKUP] Created backup: {backup_path}")
    rotate_backups()
    return backup_path

def rotate_backups():
    files = sorted(
        [f for f in os.listdir(BACKUP_DIR) if f.endswith(".db")],
        reverse=True
    )

    if len(files) > MAX_BACKUPS:
        to_delete = files[MAX_BACKUPS:]
        for f in to_delete:
            os.remove(os.path.join(BACKUP_DIR, f))
            logger.info(f"[BACKUP] Deleted old backup: {f}")

# ---------------------------
# Recovery Testing
# ---------------------------
def test_backup_recovery(backup_path: str) -> bool:
    test_db = "temp_recovery_test.db"

    try:
        shutil.copy2(backup_path, test_db)
    except Exception as e:
        logger.error(f"[RECOVERY TEST] Failed to copy backup: {e}")
        return False

    conn = sqlite3.connect(test_db)
    c = conn.cursor()

    try:
        integrity = c.execute("PRAGMA integrity_check;").fetchone()[0]
        if integrity != "ok":
            logger.error(f"[RECOVERY TEST] Integrity check FAILED for {backup_path}")
            return False

        fk = c.execute("PRAGMA foreign_key_check;").fetchall()
        if fk:
            logger.error(f"[RECOVERY TEST] Foreign key violations: {fk}")
            return False

        c.execute("SELECT COUNT(*) FROM Users;")

        logger.info(f"[RECOVERY TEST] Backup {backup_path} restored successfully.")
        return True

    except Exception as e:
        logger.error(f"[RECOVERY TEST] Exception: {e}")
        return False

    finally:
        conn.close()
        if os.path.exists(test_db):
            os.remove(test_db)

# ---------------------------
# Scheduler
# ---------------------------
def job_backup():
    create_backup()

def job_recovery_test():
    backups = sorted(os.listdir(BACKUP_DIR))
    if not backups:
        logger.error("[SCHEDULE] No backups available for recovery test")
        return

    latest = os.path.join(BACKUP_DIR, backups[-1])
    test_backup_recovery(latest)

def start_scheduler():
    schedule.every(6).hours.do(job_backup)
    schedule.every().day.at("03:00").do(job_recovery_test)

    logger.info("Backup scheduler started...")

    while True:
        schedule.run_pending()
        time.sleep(2)

if __name__ == "__main__":
    start_scheduler()