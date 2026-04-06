import os
from datetime import datetime

LOG_FILE = "logs/activity.log"
REPORT_FILE = "logs/final_report.txt"   # ADD THIS


def generate_report():
    if not os.path.exists(LOG_FILE):
        print("No logs available")
        return

    total_events = 0
    total_alerts = 0
    high = medium = low = critical = 0
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

        # Count severity
        if severity == "HIGH":
            high += 1
            incidents.append(f"[HIGH] {event} -> {file_path}")
        elif severity == "MEDIUM":
            medium += 1
        elif severity == "CRITICAL":
            critical += 1
            incidents.append(f"[CRITICAL] {event} -> {file_path}")
        else:
            low += 1

        # Count alerts
        if severity in ["HIGH", "CRITICAL"]:
            total_alerts += 1

        # Event breakdown
        event_counts[event] = event_counts.get(event, 0) + 1

    # -------------------------------
    # Build report content
    # -------------------------------
    report = "========== SECURITY AUDIT REPORT ==========\n"
    report += f"Generated On: {datetime.now()}\n\n"

    report += "--- SUMMARY ---\n"
    report += f"Total Events: {total_events}\n"
    report += f"Total Alerts: {total_alerts}\n"
    report += f"HIGH: {high}, MEDIUM: {medium}, LOW: {low}, CRITICAL: {critical}\n\n"

    report += "--- EVENT BREAKDOWN ---\n"
    for event, count in event_counts.items():
        report += f"{event}: {count}\n"

    report += "\n--- SECURITY INCIDENTS ---\n"
    for incident in incidents:
        report += incident + "\n"

    # -------------------------------
    # Save to file IMPORTANT
    # -------------------------------
    if not os.path.exists("logs"):
        os.makedirs("logs")

    with open(REPORT_FILE, "w") as f:
        f.write(report)

    # -------------------------------
    # Print also (optional)
    # -------------------------------
    print(report)
    print(f"[+] Report saved at: {REPORT_FILE}")
