from collections import defaultdict
from datetime import datetime, timedelta
import os
import re
import shutil
import subprocess
import sys

LOG_PATH = "C:/Users/PC/Downloads/auth.log" # Path to the SSH authentication log file (fake one here for testing) for centOS, Ubuntu, Debian, etc. (e.g., /var/log/auth.log or /var/log/secure)
#change rules below if you want to adjust the detection sensitivity
MAX_FAILED_ATTEMPTS = 5
TIME_WINDOW_SECONDS = 60
TIME_WINDOW = timedelta(seconds=TIME_WINDOW_SECONDS)

FAILED_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r".*sshd\[\d+\]:\s+Failed\s+(?:password|publickey)\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

ip_attempts = defaultdict(list)
flagged_ips = {}
current_year = datetime.now().year


def block_ip(ip: str):
    """Detects available firewall (ufw or iptables) and blocks the IP."""
    try:
        if shutil.which("ufw"):
            cmd = ["ufw", "deny", "from", ip, "to", "any"]
        elif shutil.which("iptables"):
            cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        else:
            print(
                f"[ERROR] Neither 'ufw' nor 'iptables' found on this system.",
                file=sys.stderr,
            )
            return

        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"[BLOCKED] Successfully blocked {ip} using: {' '.join(cmd)}")
    except subprocess.CalledProcessError as e:
        print(
            f"[ERROR] Failed to block {ip}: {e.stderr.strip()}", file=sys.stderr
        )
    except PermissionError:
        print(
            f"[ERROR] Insufficient privileges. Please re-run with sudo.",
            file=sys.stderr,
        )


# --- 1. Parse log file ---
with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        match = FAILED_PATTERN.search(line)
        if not match:
            continue

        ip = match.group("ip")
        raw_time = f"{current_year} {match.group('month')} {match.group('day')} {match.group('time')}"
        dt = datetime.strptime(raw_time, "%Y %b %d %H:%M:%S")

        # Sliding window filter
        ip_attempts[ip].append(dt)
        ip_attempts[ip] = [t for t in ip_attempts[ip] if dt - t <= TIME_WINDOW]

        if len(ip_attempts[ip]) >= MAX_FAILED_ATTEMPTS and ip not in flagged_ips:   # no more than 5 attempts in the last 60 seconds
            flagged_ips[ip] = {
                "first_attempt": ip_attempts[ip][0],
                "flagged_at": dt,
                "attempts_in_window": len(ip_attempts[ip]),
            }

# --- 2. Report Findings ---
print("=" * 65)
print(
    f"SUSPICIOUS ACTIVITY REPORT (>={MAX_FAILED_ATTEMPTS} fails in {TIME_WINDOW_SECONDS}s)"
)
print("=" * 65)

if not flagged_ips:
    print("No IP addresses exceeded the failed attempt threshold.")
    sys.exit(0)

for ip, info in flagged_ips.items():
    print(f"Suspicious IP : {ip}")
    print(f"Attempts      : {info['attempts_in_window']} failures")
    print(f"Time Window   : {info['first_attempt']} -> {info['flagged_at']}")
    print("the scan is statistical and may not be accurate, please check the logs for more details")
    print("-" * 65)

# --- 3. User Confirmation & Blocking ---
print("\n[WARNING] Modifying firewall rules requires root privileges.")
choice = input(
    f"Do you want to block all {len(flagged_ips)} suspicious IP(s)? (yes/no): "
).strip().lower()

if choice in ("y", "yes"):
    if os.geteuid() != 0:
        print(
            "\n[WARNING] You are not running as root. Commands may fail if sudo access is required."
        )

    for ip in flagged_ips:
        block_ip(ip)
else:
    print("\nAction cancelled. No firewall rules were modified.")