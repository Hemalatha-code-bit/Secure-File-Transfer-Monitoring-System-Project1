import os
from datetime import datetime

LOG_FILE = "logs/activity.log"

def generate_report():
    if not os.path.exists(LOG_FILE):
        print("No logs available")
        return

    total_events = 0
    total_alerts = 0
    high = medium = low = 0
    event_counts = {}
    incidents = []

    with open(LOG_FILE, "r") as f:
        lines = f.readlines()

    for line in lines:
        total_events += 1

        parts = line.strip().split("|")
        if len(parts) < 4:
            continue

        timestamp, severity, event, file_path = [p.strip() for p in parts]

        if severity == "HIGH":
            high += 1
            incidents.append((event, file_path))
        elif severity == "MEDIUM":
            medium += 1
        else:
            low += 1

        if "VIOLATION" in event or "UNAUTHORIZED" in event:
            total_alerts += 1

        event_counts[event] = event_counts.get(event, 0) + 1

    print("\n========== SECURITY AUDIT REPORT ==========")
    print(f"Generated On: {datetime.now()}")

    print("\n--- SUMMARY ---")
    print(f"Total Events: {total_events}")
    print(f"Total Alerts: {total_alerts}")
    print(f"HIGH: {high}, MEDIUM: {medium}, LOW: {low}")

    print("\n--- EVENT BREAKDOWN ---")
    for event, count in event_counts.items():
        print(f"{event}: {count}")

    print("\n--- SECURITY INCIDENTS ---")
    for event, file_path in incidents:
        print(f"[HIGH] {event} -> {file_path}")
