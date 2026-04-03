import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from alert import generate_alert
from logger import log_event

# Deduplication set (prevents duplicate alerts)
processed_moves = set()

# -------------------------------
# Load config files
# -------------------------------
def load_file(file):
    if not os.path.exists(file):
        return []
    with open(file, "r") as f:
        return [line.strip() for line in f.readlines()]


sensitive_files = load_file("config/sensitive_files.txt")
allowed_paths = load_file("config/allowed_paths.txt")

# Store recent deletes to detect move
recent_deletes = {}
DELETE_WINDOW = 5  # seconds


class MonitorHandler(FileSystemEventHandler):

    def get_severity(self, file_path):
        file_path_lower = os.path.normpath(file_path).lower()

        is_sensitive = any(
            file_path_lower.startswith(os.path.normpath(s).lower())
            for s in sensitive_files
        )

        is_allowed = any(
            file_path_lower.startswith(os.path.normpath(a).lower())
            for a in allowed_paths
        )

        if is_sensitive and not is_allowed:
            return "HIGH"
        elif is_sensitive:
            return "MEDIUM"
        else:
            return "LOW"

    def process(self, event_type, file_path):
        file_path = os.path.normpath(file_path)
        severity = self.get_severity(file_path)
        log_event(event_type, file_path, severity)

    def on_created(self, event):
        if not event.is_directory:
            file_path = os.path.normpath(event.src_path)
            file_name = os.path.basename(file_path)

            # 🔥 Detect MOVE (delete + create correlation)
            if file_name in recent_deletes:
                src_path, delete_time = recent_deletes[file_name]

                if time.time() - delete_time <= DELETE_WINDOW:

                    move_key = f"{src_path}->{file_path}"

                    if move_key not in processed_moves:
                        processed_moves.add(move_key)

                        print(f"[>] MOVED: {src_path} -> {file_path}")

                        severity = self.get_severity(src_path)

                        log_event("MOVED", f"{src_path} -> {file_path}", severity)

                        # 🚨 Alert only if unauthorized
                        dest_lower = file_path.lower()
                        is_to_allowed = any(
                            dest_lower.startswith(os.path.normpath(a).lower())
                            for a in allowed_paths
                        )

                        if severity == "HIGH" and not is_to_allowed:
                            generate_alert("UNAUTHORIZED MOVE", file_path)

                    # cleanup
                    del recent_deletes[file_name]

                    if len(processed_moves) > 100:
                        processed_moves.clear()

                    return  # 🚨 STOP further processing (prevents CREATED log)

            # Normal create
            print(f"[+] Created: {file_path}")
            self.process("CREATED", file_path)

    def on_deleted(self, event):
        if not event.is_directory:
            file_path = os.path.normpath(event.src_path)
            file_name = os.path.basename(file_path)

            print(f"[-] Deleted: {file_path}")
            self.process("DELETED", file_path)

            # Track delete for MOVE detection
            recent_deletes[file_name] = (file_path, time.time())

    def on_modified(self, event):
        if not event.is_directory:
            file_path = os.path.normpath(event.src_path)

            # Optional: reduce noise (skip frequent duplicates later if needed)
            print(f"[*] Modified: {file_path}")
            self.process("MODIFIED", file_path)

    def on_moved(self, event):
        if not event.is_directory:
            src = os.path.normpath(event.src_path)
            dest = os.path.normpath(event.dest_path)

            print(f"[>] MOVED (native): {src} -> {dest}")

            severity = self.get_severity(src)
            log_event("MOVED", f"{src} -> {dest}", severity)


# -------------------------------
# Start monitoring
# -------------------------------
def start_monitoring():
    path = "C:/Users/Hemalatha/Documents"

    if not os.path.exists(path):
        print(f"[ERROR] Path not found: {path}")
        return

    event_handler = MonitorHandler()
    observer = Observer()

    observer.schedule(event_handler, path, recursive=True)
    observer.start()

    print(f"[+] Monitoring started on: {path}")

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[!] Stopping monitoring...")
        observer.stop()

    observer.join()
