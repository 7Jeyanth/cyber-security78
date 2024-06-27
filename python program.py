import re
import time
from datetime import datetime

# Path to the log file
log_file_path = 'network_traffic.log'
alert_log_path = 'alerts.log'

# Patterns to detect suspicious activity
suspicious_patterns = {
    'Failed Login Attempt': r'POST /login.php HTTP/1.1\" 401',
    'Forbidden Access Attempt': r'POST /admin.html HTTP/1.1\" 403',
    'Accessing Sensitive Data': r'GET /sensitive_data HTTP/1.1\" 200'
}

def read_logs(file_path):
    """Read the logs from the file."""
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

def monitor_logs(logs):
    """Monitor logs for suspicious activity."""
    for log in logs:
        for activity, pattern in suspicious_patterns.items():
            if re.search(pattern, log):
                alert(activity, log)

def alert(activity, log):
    """Generate an alert and log it to a file."""
    alert_message = f"[{datetime.now()}] ALERT: {activity} detected: {log.strip()}\n"
    print(alert_message)
    with open(alert_log_path, 'a') as alert_file:
        alert_file.write(alert_message)

# Main function to run the monitoring system
if __name__ == "__main__":
    print("Starting network traffic monitoring system...")
    while True:
        logs = read_logs(log_file_path)
        monitor_logs(logs)
        time.sleep(10)  # Simulate continuous monitoring with a delay
        # For demonstration purposes, break after the first iteration
        break
