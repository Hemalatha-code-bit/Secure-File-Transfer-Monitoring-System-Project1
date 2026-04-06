import json
import os
from hashing import calculate_hash
from alert import generate_alert

HASH_FILE = "hash_store.json"


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

    # First time → store hash only
    if file_path not in hashes:
        hashes[file_path] = new_hash
        save_hashes(hashes)
        return

    old_hash = hashes[file_path]

    # 🔴 Integrity violation → CRITICAL
    if old_hash != new_hash:
        generate_alert(
            "INTEGRITY VIOLATION",
            file_path,
            "CRITICAL"
        )

    # Always update hash
    hashes[file_path] = new_hash
    save_hashes(hashes)
