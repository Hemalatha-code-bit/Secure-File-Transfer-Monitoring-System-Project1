from logger import log_event

def generate_alert(alert_type, file_path, severity="HIGH"):
    print(f"[ALERT] {severity} | {alert_type} -> {file_path}")

    # Log alert also
    log_event(alert_type, file_path, severity)
