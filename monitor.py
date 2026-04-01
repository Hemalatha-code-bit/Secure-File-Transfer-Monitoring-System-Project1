import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

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
            file_path = os.path.normpath(file_path)
            log_event(event_type, file_path)
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
            src_path = os.path.normpath(event.src_path)
            dest_path = os.path.normpath(event.dest_path)

            src_name = os.path.basename(src_path)
            dest_name = os.path.basename(dest_path)

            print(f"[>] Moved: {src_name} -> {dest_name}")

            # Log movement
            log_event("MOVED", dest_path)

            # Detect conditions
            is_from_sensitive = any(s in src_path for s in sensitive_files)
            is_to_sensitive = any(s in dest_path for s in sensitive_files)
            is_to_allowed = any(a in dest_path for a in allowed_paths)

            # CASE 1: Sensitive → Non-Allowed (UNAUTHORIZED)
            if is_from_sensitive and not is_to_allowed:
                print(f"[ALERT] UNAUTHORIZED MOVE -> {dest_path}")
                generate_alert("UNAUTHORIZED MOVE", dest_path)

            # CASE 2: File moved INTO sensitive folder
            elif is_to_sensitive:
                print(f"[ALERT] FILE MOVED INTO SENSITIVE AREA -> {dest_path}")
                generate_alert("MOVE TO SENSITIVE", dest_path)

            # CASE 3: File moved OUT of sensitive folder (allowed)
            elif is_from_sensitive and is_to_allowed:
                print(f"[INFO] Sensitive file moved to allowed location -> {dest_path}")


def start_monitoring():
    path = "C:/Users/Hemalatha/Documents"

    if not os.path.exists(path):
        print(f"[ERROR] Path not found: {path}")
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
