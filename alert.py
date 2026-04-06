from logger import log_event


def generate_alert(alert_type, file_path, severity="HIGH"):
    # Print alert message
    print(f"[ALERT] {alert_type} -> {file_path}")

    # Log event with severity
    log_event(alert_type, file_path, severity)
