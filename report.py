import os
from collections import Counter

LOG_FILE = "logs/activity.log"


def generate_report():
    if not os.path.exists(LOG_FILE):
        print("[ERROR] No logs found.")
        return

    with open(LOG_FILE, "r") as f:
        lines = f.readlines()

    total_events = len(lines)

    # Counters
    severity_count = Counter()
    event_types = Counter()

    for line in lines:
        parts = line.strip().split("|")

        if len(parts) >= 3:
            severity = parts[0].strip()
            event_type = parts[1].strip()

            severity_count[severity] += 1
            event_types[event_type] += 1

    print("\n===== FINAL AUDIT REPORT =====")
    print(f"Total Events: {total_events}")

    print("\n--- Severity Breakdown ---")
    for key, value in severity_count.items():
        print(f"{key}: {value}")

    print("\n--- Event Type Breakdown ---")
    for key, value in event_types.items():
        print(f"{key}: {value}")

    print("\n===== END OF REPORT =====")
