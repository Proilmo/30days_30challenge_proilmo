#!/usr/bin/env python3
import os
import re
import sys
from pathlib import Path

# Paths commonly used for systemd persistence
SYSTEMD_SYSTEM_DIRS = [
    "/etc/systemd/system",
    "/usr/local/lib/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/run/systemd/system",
]

SYSTEMD_GENERATOR_DIRS = [
    "/etc/systemd/system-generators",
    "/usr/local/lib/systemd/system-generators",
    "/lib/systemd/system-generators",
    "/usr/lib/systemd/system-generators",
]

SUSPICIOUS_EXEC_PATTERNS = [
    r"/tmp/",
    r"/dev/shm/",
    r"/var/tmp/",
    r"curl\s+",
    r"wget\s+",
    r"base64\s+-d",
    r"python[23]?\s+-c",
    r"perl\s+-e",
    r"bash\s+-i",
    r"nc(\.traditional|\.openbsd)?\s+",
    r"/dev/tcp/",
]

def scan_user_systemd_dirs():
    """Locate user-level systemd configuration directories."""
    user_dirs = []
    home_path = Path("/home")
    if home_path.exists():
        for user_dir in home_path.iterdir():
            user_config = user_dir / ".config" / "systemd" / "user"
            if user_config.is_dir():
                user_dirs.append(str(user_config))
    
    root_user_config = Path("/root/.config/systemd/user")
    if root_user_config.is_dir():
        user_dirs.append(str(root_user_config))
        
    return user_dirs

def parse_service_file(file_path):
    """Extract ExecStart, ExecStartPre, ExecStartPost, and WantedBy targets."""
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, 1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#"):
                    continue
                
                # Check for execution directives
                if re.match(r"^Exec(Start|StartPre|StartPost|Reload|Stop|StopPost)=", clean_line, re.IGNORECASE):
                    val = clean_line.split("=", 1)[1].strip()
                    findings.append((line_no, clean_line.split("=")[0], val))
    except Exception as e:
        pass
    return findings

def inspect_unit_directory(target_dir):
    """Scan a directory for unit files, timers, overrides, and suspicious commands."""
    alerts = []
    p = Path(target_dir)
    if not p.exists():
        return alerts

    for item in p.rglob("*"):
        if item.is_file():
            # Flag generators (executable scripts run at boot to dynamically create units)
            if "system-generators" in str(item):
                alerts.append({
                    "level": "HIGH",
                    "file": str(item),
                    "reason": "Systemd Generator script discovered (executes during early boot phase).",
                    "detail": f"Permissions: {oct(item.stat().st_mode)[-3:]}"
                })
                continue

            # Parse unit files (.service, .timer, .conf drop-ins)
            if item.suffix in [".service", ".timer", ".conf", ".target", ".path"]:
                commands = parse_service_file(item)
                for line_no, directive, cmd in commands:
                    for pattern in SUSPICIOUS_EXEC_PATTERNS:
                        if re.search(pattern, cmd, re.IGNORECASE):
                            alerts.append({
                                "level": "HIGH",
                                "file": f"{item}:{line_no}",
                                "reason": f"Suspicious command matching pattern '{pattern}'",
                                "detail": f"{directive}={cmd}"
                            })
                            break
                    
                    # Highlight items in /tmp or writable world directories
                    if any(cmd.strip().startswith(prefix) for prefix in ["/tmp", "/dev/shm", "/var/tmp"]):
                        alerts.append({
                            "level": "CRITICAL",
                            "file": f"{item}:{line_no}",
                            "reason": "Executable points to temporary/world-writable storage",
                            "detail": f"{directive}={cmd}"
                        })

    return alerts

def main():
    print("[*] Starting Systemd Persistence & Anomaly Scanner...\n")
    
    if os.geteuid() != 0:
        print("[!] Warning: Running as non-root. Some system directories may not be readable.\n")

    all_dirs = SYSTEMD_SYSTEM_DIRS + SYSTEMD_GENERATOR_DIRS + scan_user_systemd_dirs()
    total_findings = 0

    for scan_path in all_dirs:
        if not os.path.exists(scan_path):
            continue
            
        print(f"[*] Checking directory: {scan_path}")
        results = inspect_unit_directory(scan_path)
        
        for res in results:
            total_findings += 1
            print(f"  [{res['level']}] {res['reason']}")
            print(f"      Location: {res['file']}")
            print(f"      Content:  {res['detail']}\n")

    print("=" * 60)
    print(f"Scan complete. Found {total_findings} potential indicator(s) of persistence.")
    print("=" * 60)

if __name__ == "__main__":
    main()