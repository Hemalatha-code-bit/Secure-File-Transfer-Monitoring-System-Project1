import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "activity.log")

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)


def log_event(event_type, file_path):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"{timestamp} | {event_type} | {file_path}\n"

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_message)

    print(f"[LOGGED] {event_type} | {file_path}")
