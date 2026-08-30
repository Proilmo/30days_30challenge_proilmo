"""
persistence_scanner_lib.py
---------------------------
This is Day 10's Systemd_Persistence_Scanner.py, refactored so its detection
logic can be called as a library function that RETURNS findings, instead of
a standalone script that only prints them. Nothing about the detection
logic itself was changed -- same directories, same suspicious-exec regex
list, same CRITICAL/HIGH levels. It just now hands its results to whoever
called it (the SIEM collector) instead of the console.
"""

import re
from pathlib import Path

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
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, 1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#"):
                    continue
                if re.match(r"^Exec(Start|StartPre|StartPost|Reload|Stop|StopPost)=", clean_line, re.IGNORECASE):
                    val = clean_line.split("=", 1)[1].strip()
                    findings.append((line_no, clean_line.split("=")[0], val))
    except Exception:
        pass
    return findings


def inspect_unit_directory(target_dir):
    alerts = []
    p = Path(target_dir)
    if not p.exists():
        return alerts

    for item in p.rglob("*"):
        if item.is_file():
            if "system-generators" in str(item):
                alerts.append({
                    "level": "HIGH",
                    "file": str(item),
                    "reason": "Systemd Generator script discovered (executes during early boot phase).",
                    "detail": f"Permissions: {oct(item.stat().st_mode)[-3:]}",
                })
                continue

            if item.suffix in [".service", ".timer", ".conf", ".target", ".path"]:
                commands = parse_service_file(item)
                for line_no, directive, cmd in commands:
                    for pattern in SUSPICIOUS_EXEC_PATTERNS:
                        if re.search(pattern, cmd, re.IGNORECASE):
                            alerts.append({
                                "level": "HIGH",
                                "file": f"{item}:{line_no}",
                                "reason": f"Suspicious command matching pattern '{pattern}'",
                                "detail": f"{directive}={cmd}",
                            })
                            break
                    if any(cmd.strip().startswith(prefix) for prefix in ["/tmp", "/dev/shm", "/var/tmp"]):
                        alerts.append({
                            "level": "CRITICAL",
                            "file": f"{item}:{line_no}",
                            "reason": "Executable points to temporary/world-writable storage",
                            "detail": f"{directive}={cmd}",
                        })
    return alerts


def run_full_scan(extra_dirs=None, scan_real_system=True):
    """Scan all standard systemd locations (plus any extra_dirs given, which
    is how the SIEM demo points this at a fake sample directory instead of
    the real filesystem). Returns a flat list of finding dicts.

    scan_real_system=False skips the real /etc|/usr/lib systemd directories
    entirely and only looks at extra_dirs. That's what the bundled demo
    uses, on purpose: this sandbox/container already has dozens of
    perfectly legitimate systemd generator scripts, and the original
    Day 10 logic (kept as-is here) flags EVERY generator it finds as a
    HIGH finding regardless of content -- great for a real host where
    generators are rare and worth a human glance, but noisy in a
    throwaway demo environment. On a real machine you'd want
    scan_real_system=True (the default) so it also checks the actual
    boot-time locations, not just your test directory."""
    all_dirs = list(extra_dirs) if extra_dirs else []
    if scan_real_system:
        all_dirs += SYSTEMD_SYSTEM_DIRS + SYSTEMD_GENERATOR_DIRS + scan_user_systemd_dirs()
    results = []
    for d in all_dirs:
        results.extend(inspect_unit_directory(d))
    return results
