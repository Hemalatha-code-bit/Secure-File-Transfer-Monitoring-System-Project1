import json
import os
from hashing import calculate_hash
from alert import generate_alert

HASH_FILE = "hash_store.json"

# Prevent duplicate alerts
alerted_files = set()


def load_hashes():
    if not os.path.exists(HASH_FILE):
        return {}
    with open(HASH_FILE, "r") as f:
        return json.load(f)


def save_hashes(data):
    with open(HASH_FILE, "w") as f:
        json.dump(data, f, indent=4)


def check_integrity(file_path):
    if not os.path.exists(file_path):
        return

    hashes = load_hashes()
    new_hash = calculate_hash(file_path)

    # First time → just store hash (NO alert)
    if file_path not in hashes:
        hashes[file_path] = new_hash
        save_hashes(hashes)
        return

    old_hash = hashes[file_path]

    # Only alert if hash actually changed
    if old_hash != new_hash:
        if file_path not in alerted_files:
            generate_alert("INTEGRITY VIOLATION", file_path, "HIGH")
            alerted_files.add(file_path)

    # Update hash after check
    hashes[file_path] = new_hash
    save_hashes(hashes)
