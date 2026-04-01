import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from integrity import check_integrity
from alert import generate_alert
from logger import log_event
from report import generate_report   # ✅ FIXED (moved to top)

# Deduplication set
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

recent_deletes = {}
DELETE_WINDOW = 5


class MonitorHandler(FileSystemEventHandler):

    def process(self, event_type, file_path):
        file_path = os.path.normpath(file_path)
        log_event(event_type, file_path, "LOW")   # ✅ added severity

    def is_sensitive(self, file_path):
        file_path_lower = file_path.lower()
        return any(file_path_lower.startswith(os.path.normpath(s).lower()) for s in sensitive_files)

    def is_allowed(self, file_path):
        file_path_lower = file_path.lower()
        return any(file_path_lower.startswith(os.path.normpath(a).lower()) for a in allowed_paths)

    def on_created(self, event):
        if not event.is_directory:
            file_path = os.path.normpath(event.src_path)
            file_name = os.path.basename(file_path)

            print(f"[+] Created: {file_path}")
            self.process("CREATED", file_path)

            if os.path.exists(file_path):
                check_integrity(file_path)

            # 🚨 Sensitive access
            if self.is_sensitive(file_path) and not self.is_allowed(file_path):
                generate_alert("UNAUTHORIZED ACCESS TO SENSITIVE FILE", file_path, "MEDIUM")

            # Move detection
            if file_name in recent_deletes:
                src_path, delete_time = recent_deletes[file_name]

                if time.time() - delete_time <= DELETE_WINDOW:

                    print(f"[>] Moved (detected): {src_path} -> {file_path}")

                    move_key = f"{src_path}->{file_path}"

                    if self.is_sensitive(src_path) and not self.is_allowed(file_path) and move_key not in processed_moves:
                        processed_moves.add(move_key)
                        generate_alert("UNAUTHORIZED MOVE", file_path, "HIGH")

                        if len(processed_moves) > 100:
                            processed_moves.clear()

                del recent_deletes[file_name]

    def on_deleted(self, event):
        if not event.is_directory:
            file_path = os.path.normpath(event.src_path)
            file_name = os.path.basename(file_path)

            print(f"[-] Deleted: {file_path}")
            self.process("DELETED", file_path)

            recent_deletes[file_name] = (file_path, time.time())

    def on_modified(self, event):
        if not event.is_directory:
            file_path = os.path.normpath(event.src_path)

            print(f"[*] Modified: {file_path}")
            self.process("MODIFIED", file_path)

            if os.path.exists(file_path):
                check_integrity(file_path)

            if self.is_sensitive(file_path) and not self.is_allowed(file_path):
                generate_alert("UNAUTHORIZED ACCESS TO SENSITIVE FILE", file_path, "MEDIUM")

    def on_moved(self, event):
        if not event.is_directory:
            src = os.path.normpath(event.src_path)
            dest = os.path.normpath(event.dest_path)

            print(f"[>] Moved: {src} -> {dest}")
            log_event("MOVED", dest, "LOW")

            if os.path.exists(dest):
                check_integrity(dest)


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

        # ✅ Generate report correctly
        generate_report()

    observer.join()
