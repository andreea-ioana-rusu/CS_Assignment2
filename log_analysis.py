import sys
import re
from collections import defaultdict

# Event type keywords
EVENT_TYPES = {
    "SUCCESSFUL_LOGIN": r"Accepted password for root",
    "FILE_DOWNLOAD": r"\b(wget|curl)\b",
    "PERMISSION_CHANGE": r"chmod \+x",
    "SCRIPT_EXECUTION": r"\./\w+\.sh",
    "ENCRYPTION_ACTIVITY": r"(encryptor|\.locked)",
    "PERSISTENCE_MECHANISM": r"CRON.*(@reboot|/nonstandard|/evil\.sh)"
}

def parse_log(file_path):
    failed_logins = defaultdict(int)
    suspicious_events = []
    total_entries = 0
    total_failed_logins = 0

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            total_entries += 1

            # Detect failed SSH login attempts
            if "Failed password" in line:
                total_failed_logins += 1
                ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    ip = ip_match.group(1)
                    failed_logins[ip] += 1

            # Detect ransomware-related events
            for event, pattern in EVENT_TYPES.items():
                if re.search(pattern, line):
                    timestamp_match = re.match(r"^[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}", line)
                    timestamp = timestamp_match.group(0) if timestamp_match else "Unknown"
                    suspicious_events.append((timestamp, event, line.strip()))
                    break

    return failed_logins, suspicious_events, total_entries, total_failed_logins

def print_failed_logins(failed_logins):
    print("\nSuspicious IPs with failed logins:")
    brute_force_ips = []
    for ip, count in failed_logins.items():
        if count > 5:
            print(f"{ip} - {count} failed login attempts - Possible Brute Force Attack")
            brute_force_ips.append(ip)
    return brute_force_ips

def print_suspicious_events(events):
    print("\nSuspicious Events Summary:")
    print("-" * 50)
    for timestamp, event_type, message in events:
        print(f"{timestamp} - {event_type} - {message}")

def print_summary(total_entries, total_failed_logins, brute_force_ips, events):
    print("\nLog Analysis Summary")
    print("-" * 50)
    print(f"Total log entries analyzed: {total_entries}")
    print(f"Failed SSH login attempts: {total_failed_logins}")
    print(f"IPs flagged for possible brute force attacks: {len(brute_force_ips)}")
    for ip in brute_force_ips:
        print(ip)
    print(f"Suspicious ransomware-related events detected: {len(events)}")

    # Count event types
    event_counts = defaultdict(int)
    for _, event_type, _ in events:
        event_counts[event_type] += 1

    for event_type, count in event_counts.items():
        print(f"{count} {event_type.replace('_', ' ').lower()}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python log_analysis.py <log_file>")
        sys.exit(1)

    log_file = sys.argv[1]
    failed_logins, suspicious_events, total_entries, total_failed_logins = parse_log(log_file)
    brute_force_ips = print_failed_logins(failed_logins)
    print_suspicious_events(suspicious_events)
    print_summary(total_entries, total_failed_logins, brute_force_ips, suspicious_events)