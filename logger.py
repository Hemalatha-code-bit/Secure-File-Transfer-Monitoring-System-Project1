import logging
import os

log_dir = "logs"
log_file = os.path.join(log_dir, "activity.log")

if not os.path.exists(log_dir):
    os.makedirs(log_dir)

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    force=True
)

def log_event(event_type, file_path):
    message = f"{event_type} | {file_path}"
    logging.info(message)
    print(f"[LOGGED] {message}")
