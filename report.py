import os

LOG_FILE = "logs/activity.log"

def generate_report():
    if not os.path.exists(LOG_FILE):
        print("No logs found.")
        return

    total_events = 0
    total_alerts = 0
    high_severity = 0

    event_counts = {}

    with open(LOG_FILE, "r") as f:
        lines = f.readlines()

    for line in lines:
        total_events += 1

        parts = line.strip().split("|")
        if len(parts) < 4:
            continue

        severity = parts[1].strip()
        event = parts[2].strip()

        # Count alerts
        if "VIOLATION" in event or "UNAUTHORIZED" in event:
            total_alerts += 1

        if severity == "HIGH":
            high_severity += 1

        # Count event types
        event_counts[event] = event_counts.get(event, 0) + 1

    print("\n====== SECURITY REPORT ======")
    print(f"Total Events: {total_events}")
    print(f"Total Alerts: {total_alerts}")
    print(f"High Severity Events: {high_severity}")

    print("\nEvent Breakdown:")
    for event, count in event_counts.items():
        print(f"{event}: {count}")
