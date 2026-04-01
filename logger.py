import logging
import os

log_dir = "logs"
log_file = os.path.join(log_dir, "activity.log")

# Ensure logs folder exists
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Setup logging (force=True is important)
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    force=True
)

def log_event(event_type, file_path, hash_value):
    message = f"{event_type} | {file_path} | HASH: {hash_value}"
    logging.info(message)
    print(f"[LOGGED] {message}")  # 👈 VERY IMPORTANT (debug)
