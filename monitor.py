import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from hashing import calculate_hash
from alert import generate_alert
from logger import log_event


# Load config
def load_file(file):
    if not os.path.exists(file):
        return []
    with open(file, "r") as f:
        return [line.strip() for line in f.readlines()]


sensitive_files = load_file("config/sensitive_files.txt")
allowed_paths = load_file("config/allowed_paths.txt")


class MonitorHandler(FileSystemEventHandler):

    def process(self, event_type, file_path):
        try:
            # Normalize path (important for Windows)
            file_path = os.path.normpath(file_path)

            hash_value = calculate_hash(file_path) if os.path.exists(file_path) else "N/A"

            is_sensitive = any(file_path.startswith(os.path.normpath(s)) for s in sensitive_files)
            is_allowed = any(file_path.startswith(os.path.normpath(a)) for a in allowed_paths)

            log_event(event_type, file_path, hash_value)

            if is_sensitive and not is_allowed:
                generate_alert(event_type, file_path)

        except Exception as e:
            print(f"[ERROR] {e}")


    def on_created(self, event):
        if not event.is_directory:
            print(f"[+] Created: {event.src_path}")
            self.process("CREATED", event.src_path)


    def on_deleted(self, event):
        if not event.is_directory:
            print(f"[-] Deleted: {event.src_path}")
            self.process("DELETED", event.src_path)


    def on_modified(self, event):
        if not event.is_directory:
            print(f"[*] Modified: {event.src_path}")
            self.process("MODIFIED", event.src_path)


    def on_moved(self, event):
        if not event.is_directory:
            # ✅ FIX: replaced Unicode arrow with ASCII
            print(f"[>] Moved: {event.src_path} -> {event.dest_path}")
            self.process("MOVED", event.dest_path)


def start_monitoring():
    path = "C:/Users/Hemalatha/Documents"  # change if needed

    if not os.path.exists(path):
        print(f"[ERROR] Path does not exist: {path}")
        return

    event_handler = MonitorHandler()
    observer = Observer()

    observer.schedule(event_handler, path, recursive=True)
    observer.start()

    print("[+] Starting Secure File Monitoring System...")
    print(f"[+] Monitoring started on: {path}")

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[!] Stopping monitoring...")
        observer.stop()

    observer.join()
