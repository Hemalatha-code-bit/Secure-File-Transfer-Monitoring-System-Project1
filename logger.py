import logging
import os

if not os.path.exists("logs"):
    os.makedirs("logs")

logging.basicConfig(
    filename="logs/activity.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

def log_event(event_type, file_path, hash_value):
    logging.info(f"{event_type} | {file_path} | HASH: {hash_value}")
