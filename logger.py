import os
from datetime import datetime

LOG_FILE = "logs/activity.log"

# Create logs folder if not exists
if not os.path.exists("logs"):
    os.makedirs("logs")


def log_event(event_type, file_path):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_message = f"{timestamp} | {event_type} | {file_path}\n"

    with open(LOG_FILE, "a") as f:
        f.write(log_message)
