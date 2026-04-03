from logger import log_event

def generate_alert(alert_type, file_path):
    # Exact required format
    print(f"[ALERT] {alert_type} -> {file_path}")

    # Also log it (important)
    log_event(alert_type, file_path, "HIGH")
