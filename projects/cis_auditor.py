#!/usr/bin/env python3
"""
CIS Linux Hardening Auditor
============================
Single-file, dependency-free (stdlib only) auditor inspired by the structure
of CIS Benchmarks. Read-only by design: it NEVER modifies the system.

Usage:
    python3 cis_auditor.py                     # run all applicable checks
    python3 cis_auditor.py --level 1            # only Level 1 checks
    python3 cis_auditor.py --profile server      # server profile only
    python3 cis_auditor.py --category ssh        # filter by category
    python3 cis_auditor.py --list                # list checks, don't run
    python3 cis_auditor.py --output json --outfile report.json
    python3 cis_auditor.py --output html --outfile report.html

Design:
    - Each control is a plain function decorated with @check(...).
    - A function returns a Result(status, details) where status is one of
      PASS / FAIL / WARN / NA / ERROR.
    - Checks are pure read operations (file reads, sysctl -a, systemctl
      is-active, etc.) executed with timeouts and full exception handling.
    - This is a SKELETON: extend CHECKS by adding more @check functions,
      one per CIS control you want to cover. Keep one function = one control.

Author: you. License: do whatever you want with it.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Callable, Optional


# --------------------------------------------------------------------------- #
# Core data model
# --------------------------------------------------------------------------- #

class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    NA = "NA"       # not applicable to this system/profile
    ERROR = "ERROR"  # check itself could not run (permissions, missing tool...)


@dataclass
class Result:
    status: Status
    details: str = ""


@dataclass
class CheckDef:
    id: str                 # CIS-style id, e.g. "1.1.1.1"
    title: str
    level: int               # 1 or 2
    profile: str              # "server", "workstation", or "all"
    category: str
    func: Callable[[], Result]
    remediation: str = ""


CHECKS: list[CheckDef] = []


def check(id: str, title: str, level: int = 1, profile: str = "all",
          category: str = "general", remediation: str = ""):
    """Decorator to register a control."""
    def wrapper(func: Callable[[], Result]):
        CHECKS.append(CheckDef(id, title, level, profile, category, func, remediation))
        return func
    return wrapper


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def run(cmd: list[str], timeout: int = 5) -> tuple[int, str, str]:
    """Run a command safely, return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def read_file(path: str) -> Optional[str]:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except (FileNotFoundError, PermissionError):
        return None


def file_mode_ok(path: str, max_mode: int) -> Optional[bool]:
    """Return True if file perms are <= max_mode (numeric, e.g. 0o644)."""
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
        return mode <= max_mode
    except FileNotFoundError:
        return None


def sysctl_value(name: str) -> Optional[str]:
    rc, out, _ = run(["sysctl", "-n", name])
    return out if rc == 0 else None


def service_active(name: str) -> Optional[bool]:
    rc, out, _ = run(["systemctl", "is-active", name])
    if rc == 127:
        return None
    return out.strip() == "active"


def service_enabled(name: str) -> Optional[bool]:
    rc, out, _ = run(["systemctl", "is-enabled", name])
    if rc == 127:
        return None
    return out.strip() in ("enabled", "static")


def mount_options(mountpoint: str) -> Optional[list[str]]:
    content = read_file("/proc/mounts")
    if content is None:
        return None
    for line in content.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[1] == mountpoint:
            return parts[3].split(",")
    return None


def sshd_config() -> dict[str, str]:
    """Parse /etc/ssh/sshd_config into a dict (case-insensitive keys)."""
    content = read_file("/etc/ssh/sshd_config")
    result: dict[str, str] = {}
    if not content:
        return result
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^(\S+)\s+(.+)$", line)
        if m:
            result[m.group(1).lower()] = m.group(2).strip()
    return result


def is_root() -> bool:
    return os.geteuid() == 0


# --------------------------------------------------------------------------- #
# CHECKS - Filesystem
# --------------------------------------------------------------------------- #

@check("1.1.1", "Ensure /tmp is mounted with noexec", level=1, profile="all",
       category="filesystem",
       remediation="Add 'noexec' to /tmp mount options in /etc/fstab and remount.")
def chk_tmp_noexec() -> Result:
    opts = mount_options("/tmp")
    if opts is None:
        return Result(Status.NA, "/tmp is not a separate mount point")
    if "noexec" in opts:
        return Result(Status.PASS, "/tmp mounted with noexec")
    return Result(Status.FAIL, f"/tmp options: {','.join(opts)}")


@check("1.1.2", "Ensure /tmp is mounted with nodev", level=1, profile="all",
       category="filesystem",
       remediation="Add 'nodev' to /tmp mount options in /etc/fstab and remount.")
def chk_tmp_nodev() -> Result:
    opts = mount_options("/tmp")
    if opts is None:
        return Result(Status.NA, "/tmp is not a separate mount point")
    if "nodev" in opts:
        return Result(Status.PASS, "/tmp mounted with nodev")
    return Result(Status.FAIL, f"/tmp options: {','.join(opts)}")


@check("1.1.3", "Ensure /home is mounted with nodev", level=1, profile="all",
       category="filesystem",
       remediation="Add 'nodev' to /home mount options in /etc/fstab and remount.")
def chk_home_nodev() -> Result:
    opts = mount_options("/home")
    if opts is None:
        return Result(Status.NA, "/home is not a separate mount point")
    if "nodev" in opts:
        return Result(Status.PASS, "/home mounted with nodev")
    return Result(Status.FAIL, f"/home options: {','.join(opts)}")


@check("6.1.1", "Ensure permissions on /etc/passwd are 644 or stricter", level=1,
       profile="all", category="filesystem",
       remediation="chmod 644 /etc/passwd")
def chk_passwd_perms() -> Result:
    ok = file_mode_ok("/etc/passwd", 0o644)
    if ok is None:
        return Result(Status.ERROR, "/etc/passwd not found")
    return Result(Status.PASS if ok else Status.FAIL,
                  f"mode={oct(stat.S_IMODE(os.stat('/etc/passwd').st_mode))}")


@check("6.1.2", "Ensure permissions on /etc/shadow are 640 or stricter", level=1,
       profile="all", category="filesystem",
       remediation="chmod 640 /etc/shadow; chown root:shadow /etc/shadow")
def chk_shadow_perms() -> Result:
    ok = file_mode_ok("/etc/shadow", 0o640)
    if ok is None:
        return Result(Status.ERROR, "/etc/shadow not found or unreadable")
    return Result(Status.PASS if ok else Status.FAIL,
                  f"mode={oct(stat.S_IMODE(os.stat('/etc/shadow').st_mode))}")


@check("6.1.3", "Ensure /etc/gshadow permissions are configured", level=1,
       profile="all", category="filesystem",
       remediation="chmod 640 /etc/gshadow")
def chk_gshadow_perms() -> Result:
    ok = file_mode_ok("/etc/gshadow", 0o640)
    if ok is None:
        return Result(Status.ERROR, "/etc/gshadow not found or unreadable")
    return Result(Status.PASS if ok else Status.FAIL,
                  f"mode={oct(stat.S_IMODE(os.stat('/etc/gshadow').st_mode))}")


# --------------------------------------------------------------------------- #
# CHECKS - Network / kernel parameters
# --------------------------------------------------------------------------- #

@check("3.2.1", "Ensure IP forwarding is disabled", level=1, profile="workstation",
       category="network",
       remediation="sysctl -w net.ipv4.ip_forward=0 and persist in /etc/sysctl.conf")
def chk_ip_forward() -> Result:
    val = sysctl_value("net.ipv4.ip_forward")
    if val is None:
        return Result(Status.ERROR, "sysctl unavailable")
    return Result(Status.PASS if val == "0" else Status.FAIL, f"value={val}")


@check("3.2.2", "Ensure ICMP redirects are not accepted", level=1, profile="all",
       category="network",
       remediation="sysctl -w net.ipv4.conf.all.accept_redirects=0")
def chk_icmp_redirects() -> Result:
    val = sysctl_value("net.ipv4.conf.all.accept_redirects")
    if val is None:
        return Result(Status.ERROR, "sysctl unavailable")
    return Result(Status.PASS if val == "0" else Status.FAIL, f"value={val}")


@check("3.2.3", "Ensure TCP SYN cookies are enabled", level=1, profile="all",
       category="network",
       remediation="sysctl -w net.ipv4.tcp_syncookies=1")
def chk_syn_cookies() -> Result:
    val = sysctl_value("net.ipv4.tcp_syncookies")
    if val is None:
        return Result(Status.ERROR, "sysctl unavailable")
    return Result(Status.PASS if val == "1" else Status.FAIL, f"value={val}")


@check("3.3.1", "Ensure a firewall is active (ufw/firewalld/nftables)", level=1,
       profile="all", category="network",
       remediation="Enable ufw, firewalld, or nftables depending on your distro.")
def chk_firewall_active() -> Result:
    for svc in ("ufw", "firewalld", "nftables"):
        active = service_active(svc)
        if active:
            return Result(Status.PASS, f"{svc} is active")
    rc, out, _ = run(["iptables", "-L", "-n"])
    if rc == 0 and "Chain INPUT" in out and "policy DROP" in out:
        return Result(Status.PASS, "iptables INPUT policy is DROP")
    return Result(Status.FAIL, "no active firewall service detected")


# --------------------------------------------------------------------------- #
# CHECKS - Logging & auditing
# --------------------------------------------------------------------------- #

@check("4.1.1", "Ensure auditd is installed and active", level=2, profile="server",
       category="logging",
       remediation="apt/yum install audit && systemctl enable --now auditd")
def chk_auditd_active() -> Result:
    active = service_active("auditd")
    if active is None:
        return Result(Status.NA, "auditd not installed")
    return Result(Status.PASS if active else Status.FAIL, f"active={active}")


@check("4.2.1", "Ensure rsyslog (or journald persistent) is active", level=1,
       profile="all", category="logging",
       remediation="systemctl enable --now rsyslog, or set Storage=persistent in journald.conf")
def chk_rsyslog_active() -> Result:
    active = service_active("rsyslog")
    if active:
        return Result(Status.PASS, "rsyslog active")
    jconf = read_file("/etc/systemd/journald.conf") or ""
    if re.search(r"^\s*Storage\s*=\s*persistent", jconf, re.MULTILINE):
        return Result(Status.PASS, "journald configured for persistent storage")
    return Result(Status.FAIL, "no persistent logging mechanism detected")


@check("4.2.2", "Ensure logrotate is configured", level=1, profile="all",
       category="logging",
       remediation="Install logrotate and ensure /etc/logrotate.conf exists.")
def chk_logrotate() -> Result:
    if shutil.which("logrotate") is None:
        return Result(Status.FAIL, "logrotate not installed")
    if os.path.exists("/etc/logrotate.conf"):
        return Result(Status.PASS, "logrotate installed and configured")
    return Result(Status.WARN, "logrotate installed but no config found")


# --------------------------------------------------------------------------- #
# CHECKS - SSH hardening
# --------------------------------------------------------------------------- #

@check("5.2.1", "Ensure SSH root login is disabled", level=1, profile="all",
       category="ssh",
       remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config")
def chk_ssh_root_login() -> Result:
    cfg = sshd_config()
    if not cfg:
        return Result(Status.NA, "sshd_config not found (SSH not installed?)")
    val = cfg.get("permitrootlogin", "yes")  # OpenSSH default is prohibit-password/yes
    if val.lower() in ("no",):
        return Result(Status.PASS, f"PermitRootLogin={val}")
    return Result(Status.FAIL, f"PermitRootLogin={val}")


@check("5.2.2", "Ensure SSH PermitEmptyPasswords is disabled", level=1, profile="all",
       category="ssh",
       remediation="Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config")
def chk_ssh_empty_passwords() -> Result:
    cfg = sshd_config()
    if not cfg:
        return Result(Status.NA, "sshd_config not found")
    val = cfg.get("permitemptypasswords", "no")
    return Result(Status.PASS if val.lower() == "no" else Status.FAIL, f"value={val}")


@check("5.2.3", "Ensure SSH MaxAuthTries is 4 or less", level=1, profile="all",
       category="ssh",
       remediation="Set 'MaxAuthTries 4' (or less) in /etc/ssh/sshd_config")
def chk_ssh_max_auth_tries() -> Result:
    cfg = sshd_config()
    if not cfg:
        return Result(Status.NA, "sshd_config not found")
    val = cfg.get("maxauthtries")
    if val is None:
        return Result(Status.WARN, "MaxAuthTries not explicitly set (default is 6)")
    try:
        n = int(val)
    except ValueError:
        return Result(Status.ERROR, f"unparsable value: {val}")
    return Result(Status.PASS if n <= 4 else Status.FAIL, f"MaxAuthTries={n}")


@check("5.2.4", "Ensure SSH X11Forwarding is disabled", level=1, profile="server",
       category="ssh",
       remediation="Set 'X11Forwarding no' in /etc/ssh/sshd_config")
def chk_ssh_x11() -> Result:
    cfg = sshd_config()
    if not cfg:
        return Result(Status.NA, "sshd_config not found")
    val = cfg.get("x11forwarding", "yes")
    return Result(Status.PASS if val.lower() == "no" else Status.FAIL, f"value={val}")


# --------------------------------------------------------------------------- #
# CHECKS - Access control / password policy
# --------------------------------------------------------------------------- #

@check("5.4.1", "Ensure password expiration is 365 days or less", level=1,
       profile="all", category="access",
       remediation="Set PASS_MAX_DAYS 365 in /etc/login.defs")
def chk_password_max_days() -> Result:
    content = read_file("/etc/login.defs")
    if content is None:
        return Result(Status.ERROR, "/etc/login.defs not found")
    m = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", content, re.MULTILINE)
    if not m:
        return Result(Status.WARN, "PASS_MAX_DAYS not set")
    days = int(m.group(1))
    return Result(Status.PASS if days <= 365 else Status.FAIL, f"PASS_MAX_DAYS={days}")


@check("5.4.2", "Ensure default user umask is 027 or stricter", level=1,
       profile="all", category="access",
       remediation="Set UMASK 027 in /etc/login.defs")
def chk_default_umask() -> Result:
    content = read_file("/etc/login.defs")
    if content is None:
        return Result(Status.ERROR, "/etc/login.defs not found")
    m = re.search(r"^\s*UMASK\s+(\d+)", content, re.MULTILINE)
    if not m:
        return Result(Status.WARN, "UMASK not set explicitly")
    umask = m.group(1)
    ok = int(umask, 8) >= 0o027
    return Result(Status.PASS if ok else Status.FAIL, f"UMASK={umask}")


@check("5.5.1", "Ensure no accounts have empty passwords", level=1, profile="all",
       category="access",
       remediation="Lock or set a password for any account with an empty password field.")
def chk_empty_password_accounts() -> Result:
    content = read_file("/etc/shadow")
    if content is None:
        return Result(Status.ERROR, "cannot read /etc/shadow (need root)")
    empty = [line.split(":")[0] for line in content.splitlines()
             if len(line.split(":")) > 1 and line.split(":")[1] == ""]
    if empty:
        return Result(Status.FAIL, f"accounts with empty password: {', '.join(empty)}")
    return Result(Status.PASS, "no empty password fields")


@check("5.5.2", "Ensure only root has UID 0", level=1, profile="all",
       category="access",
       remediation="Investigate and fix any non-root account with UID 0.")
def chk_single_uid0() -> Result:
    content = read_file("/etc/passwd")
    if content is None:
        return Result(Status.ERROR, "/etc/passwd not found")
    uid0 = [line.split(":")[0] for line in content.splitlines()
            if len(line.split(":")) > 2 and line.split(":")[2] == "0"]
    if uid0 == ["root"]:
        return Result(Status.PASS, "only root has UID 0")
    return Result(Status.FAIL, f"UID 0 accounts: {', '.join(uid0)}")


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #

def distro_info() -> dict[str, str]:
    info = {"name": platform.system(), "version": platform.release()}
    content = read_file("/etc/os-release")
    if content:
        for line in content.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                info[k] = v.strip('"')
    return info


def run_checks(level: Optional[int], profile: str, category: Optional[str]) -> list[tuple[CheckDef, Result]]:
    results = []
    for c in CHECKS:
        if level is not None and c.level != level:
            continue
        if profile != "all" and c.profile not in (profile, "all"):
            continue
        if category and c.category != category:
            continue
        try:
            res = c.func()
        except Exception as e:
            res = Result(Status.ERROR, f"exception while running check: {e}")
        results.append((c, res))
    return results


def score(results: list[tuple[CheckDef, Result]]) -> dict:
    applicable = [r for _, r in results if r.status not in (Status.NA,)]
    passed = [r for r in applicable if r.status == Status.PASS]
    total = len(applicable)
    pct = round(100 * len(passed) / total, 1) if total else 0.0
    return {
        "total_checks": len(results),
        "applicable": total,
        "passed": len(passed),
        "failed": sum(1 for r in applicable if r.status == Status.FAIL),
        "warned": sum(1 for r in applicable if r.status == Status.WARN),
        "errored": sum(1 for r in applicable if r.status == Status.ERROR),
        "score_pct": pct,
    }


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

COLORS = {
    Status.PASS: "\033[32m", Status.FAIL: "\033[31m",
    Status.WARN: "\033[33m", Status.NA: "\033[90m", Status.ERROR: "\033[35m",
}
RESET = "\033[0m"


def report_text(results, sc, meta) -> str:
    use_color = sys.stdout.isatty()
    lines = []
    lines.append(f"CIS Hardening Audit — {meta['distro']} ({meta['hostname']})")
    lines.append(f"Run at: {meta['timestamp']}   Root: {meta['is_root']}")
    lines.append("-" * 70)
    for c, r in sorted(results, key=lambda x: x[0].id):
        color = COLORS[r.status] if use_color else ""
        end = RESET if use_color else ""
        lines.append(f"[{color}{r.status.value:5s}{end}] {c.id:8s} {c.title}")
        if r.details:
            lines.append(f"           -> {r.details}")
        if r.status == Status.FAIL and c.remediation:
            lines.append(f"           fix: {c.remediation}")
    lines.append("-" * 70)
    lines.append(f"Score: {sc['score_pct']}%  "
                  f"(pass={sc['passed']} fail={sc['failed']} warn={sc['warned']} "
                  f"error={sc['errored']} na={sc['total_checks']-sc['applicable']})")
    return "\n".join(lines)


def report_json(results, sc, meta) -> str:
    payload = {
        "meta": meta,
        "score": sc,
        "results": [
            {
                "id": c.id, "title": c.title, "level": c.level, "profile": c.profile,
                "category": c.category, "status": r.status.value, "details": r.details,
                "remediation": c.remediation,
            }
            for c, r in sorted(results, key=lambda x: x[0].id)
        ],
    }
    return json.dumps(payload, indent=2)


def report_html(results, sc, meta) -> str:
    rows = ""
    badge = {"PASS": "#16a34a", "FAIL": "#dc2626", "WARN": "#d97706",
             "NA": "#9ca3af", "ERROR": "#7c3aed"}
    for c, r in sorted(results, key=lambda x: x[0].id):
        color = badge[r.status.value]
        rows += f"""
        <tr>
          <td>{c.id}</td>
          <td>{c.title}</td>
          <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{r.status.value}</span></td>
          <td>{r.details}</td>
          <td>{c.remediation}</td>
        </tr>"""
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>CIS Hardening Report</title>
<style>
body {{ font-family: -apple-system, Arial, sans-serif; background:#0b0f14; color:#e5e7eb; padding:24px; }}
h1 {{ font-size:20px; }}
table {{ width:100%; border-collapse: collapse; margin-top:16px; }}
td, th {{ padding:8px; border-bottom:1px solid #1f2937; text-align:left; font-size:13px; vertical-align:top; }}
th {{ color:#9ca3af; text-transform:uppercase; font-size:11px; }}
.score {{ font-size:32px; font-weight:700; }}
.meta {{ color:#9ca3af; font-size:13px; }}
</style></head>
<body>
<h1>CIS Hardening Audit Report</h1>
<div class="meta">{meta['distro']} — {meta['hostname']} — {meta['timestamp']}</div>
<div class="score">{sc['score_pct']}%</div>
<div class="meta">pass={sc['passed']} fail={sc['failed']} warn={sc['warned']} error={sc['errored']} / {sc['applicable']} applicable</div>
<table>
<tr><th>ID</th><th>Title</th><th>Status</th><th>Details</th><th>Remediation</th></tr>
{rows}
</table>
</body></html>"""


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(description="Single-file CIS Linux Hardening Auditor")
    parser.add_argument("--level", type=int, choices=[1, 2], default=None,
                         help="Filter by CIS level (1 or 2). Default: all.")
    parser.add_argument("--profile", choices=["all", "server", "workstation"],
                         default="all", help="Filter by profile.")
    parser.add_argument("--category", default=None,
                         help="Filter by category (filesystem, network, logging, ssh, access).")
    parser.add_argument("--output", choices=["text", "json", "html", "csv"], default="text")
    parser.add_argument("--outfile", default=None, help="Write report to file instead of stdout.")
    parser.add_argument("--list", action="store_true", help="List registered checks and exit.")
    args = parser.parse_args()

    if args.list:
        filtered = [
            c for c in CHECKS
            if (args.level is None or c.level == args.level)
            and (args.profile == "all" or c.profile in (args.profile, "all"))
            and (args.category is None or c.category == args.category)
        ]
        for c in sorted(filtered, key=lambda x: x.id):
            print(f"{c.id:8s} L{c.level} {c.profile:11s} {c.category:10s} {c.title}")
        return

    if not is_root():
        print("[!] Warning: not running as root — some checks (e.g. /etc/shadow) "
              "may report ERROR instead of a real result.\n", file=sys.stderr)

    results = run_checks(args.level, args.profile, args.category)
    sc = score(results)
    meta = {
        "hostname": platform.node(),
        "distro": distro_info().get("PRETTY_NAME", platform.platform()),
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "is_root": is_root(),
    }

    if args.output == "text":
        out = report_text(results, sc, meta)
    elif args.output == "json":
        out = report_json(results, sc, meta)
    elif args.output == "html":
        out = report_html(results, sc, meta)
    elif args.output == "csv":
        lines = ["id,title,level,profile,category,status,details"]
        for c, r in sorted(results, key=lambda x: x[0].id):
            details = r.details.replace(",", ";").replace("\n", " ")
            lines.append(f"{c.id},{c.title},{c.level},{c.profile},{c.category},{r.status.value},{details}")
        out = "\n".join(lines)

    if args.outfile:
        with open(args.outfile, "w") as f:
            f.write(out)
        print(f"Report written to {args.outfile}")
    else:
        print(out)

    # Exit code: non-zero if any FAIL, useful for CI pipelines
    sys.exit(1 if sc["failed"] > 0 else 0)


if __name__ == "__main__":
    main()
