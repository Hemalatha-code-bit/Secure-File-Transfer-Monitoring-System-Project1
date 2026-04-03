import os
from datetime import datetime

LOG_FILE = "logs/activity.log"

if not os.path.exists("logs"):
    os.makedirs("logs")

def log_event(event_type, file_path, severity="LOW"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_entry = f"{timestamp} | {severity} | {event_type} | {file_path}"

    print(f"[LOGGED] {severity} | {event_type} | {file_path}")

    with open(LOG_FILE, "a") as f:
        f.write(log_entry + "\n")
