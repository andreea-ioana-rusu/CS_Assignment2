
import re
import sys
from collections import Counter, defaultdict

# ---------------------------- PATTERNS ----------------------------
FAILED_LOGIN_PATTERN = re.compile(r"Failed password.*from (\d{1,3}(?:\.\d{1,3}){3})")
SUCCESSFUL_LOGIN_PATTERN = re.compile(r"Accepted password for root")
FILE_DOWNLOAD_PATTERN = re.compile(r"\b(wget|curl)\b")
PERMISSION_CHANGE_PATTERN = re.compile(r"chmod \+x")
SCRIPT_EXECUTION_PATTERN = re.compile(r"(\./\S+\.sh|\b\w+\.sh\b)")
ENCRYPTION_PATTERN = re.compile(r"(encryptor|\.locked)")
PERSISTENCE_PATTERN = re.compile(r"(CRON|@reboot|/etc/cron|/var/spool/cron)")

# ---------------------------- ANALYSIS ----------------------------
def analyze_log(filename):
    failed_logins = Counter()
    suspicious_events = []

    total_lines = 0
    with open(filename, "r", errors="ignore") as f:
        for line in f:
            total_lines += 1
            line = line.strip()
            if not line:
                continue

            # ---- (A) Detect Failed Logins ----
            if "Failed password" in line:
                ip_match = FAILED_LOGIN_PATTERN.search(line)
                if ip_match:
                    ip = ip_match.group(1)
                    failed_logins[ip] += 1

            # ---- (B) Detect Ransomware Indicators ----
            timestamp = " ".join(line.split()[:3]) if len(line.split()) > 2 else "N/A"

            if SUCCESSFUL_LOGIN_PATTERN.search(line):
                suspicious_events.append((timestamp, "SUCCESSFUL_LOGIN", line))
            elif FILE_DOWNLOAD_PATTERN.search(line):
                suspicious_events.append((timestamp, "FILE_DOWNLOAD", line))
            elif PERMISSION_CHANGE_PATTERN.search(line):
                suspicious_events.append((timestamp, "PERMISSION_CHANGE", line))
            elif SCRIPT_EXECUTION_PATTERN.search(line):
                suspicious_events.append((timestamp, "SCRIPT_EXECUTION", line))
            elif ENCRYPTION_PATTERN.search(line):
                suspicious_events.append((timestamp, "ENCRYPTION_ACTIVITY", line))
            elif PERSISTENCE_PATTERN.search(line):
                suspicious_events.append((timestamp, "PERSISTENCE_MECHANISM", line))

    # ---- (A) Flag Brute Force IPs ----
    flagged_ips = [ip for ip, count in failed_logins.items() if count > 5]

    return total_lines, failed_logins, flagged_ips, suspicious_events


# ---------------------------- OUTPUT ----------------------------
def print_failed_logins(failed_logins, flagged_ips):
    print("\nSuspicious IPs with failed logins:")
    for ip, count in failed_logins.items():
        flag = " - Possible Brute Force Attack" if ip in flagged_ips else ""
        print(f"{ip} - {count} failed login attempts{flag}")


def print_suspicious_events(events):
    print("\nSuspicious Events Summary:")
    print("---------------------------")
    for ts, etype, msg in events:
        print(f"{ts} - {etype} - {msg}")


def print_summary(total_lines, failed_logins, flagged_ips, events):
    print("\nLog Analysis Summary")
    print("-------------------------------")
    print(f"Total log entries analyzed: {total_lines}")
    print(f"Failed SSH login attempts: {sum(failed_logins.values())}")
    print(f"IPs flagged for possible brute force attacks: {len(flagged_ips)}")
    for ip in flagged_ips:
        print(ip)

    # count ransomware event types
    event_counts = defaultdict(int)
    for _, etype, _ in events:
        event_counts[etype] += 1

    print(f"Suspicious ransomware-related events detected: {len(events)}")
    print(f"{event_counts.get('SUCCESSFUL_LOGIN', 0)} successful root login")
    print(f"{event_counts.get('FILE_DOWNLOAD', 0)} file download")
    print(f"{event_counts.get('PERMISSION_CHANGE', 0)} permission change")
    print(f"{event_counts.get('SCRIPT_EXECUTION', 0)} script execution")
    print(f"{event_counts.get('ENCRYPTION_ACTIVITY', 0)} encryption activities")
    print(f"{event_counts.get('PERSISTENCE_MECHANISM', 0)} persistence mechanism")


# ---------------------------- MAIN ----------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python log_analysis.py access.log")
        sys.exit(1)

    logfile = sys.argv[1]
    total_lines, failed_logins, flagged_ips, events = analyze_log(logfile)

    print_failed_logins(failed_logins, flagged_ips)
    print_suspicious_events(events)
    print_summary(total_lines, failed_logins, flagged_ips, events)
