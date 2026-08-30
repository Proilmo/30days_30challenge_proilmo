#!/usr/bin/env python3
"""
run_siem.py
-----------
Main entry point. Ties together: collectors -> events table -> rule engine
-> alerts table -> HTML report.

Usage:
    python run_siem.py run                     # full pipeline, sample logs
    python run_siem.py run --auth auth.log --process process.log --firewall firewall.log
    python run_siem.py collect                 # only ingest logs, no rules
    python run_siem.py analyze                 # only run rules on existing DB
    python run_siem.py report                  # only (re)build dashboard.html

By default it points at the bundled sample_logs/ so you can see the whole
pipeline work end to end with zero setup.
"""

import argparse
import os

from siem_core import get_conn, init_db, reset_db, all_alerts
from collectors import ssh_collector, identity_collector, process_collector, \
    network_collector, persistence_collector, canary_collector
import rules
import report

DEFAULT_AUTH_LOG = os.path.join("sample_logs", "auth.log")
DEFAULT_PROCESS_LOG = os.path.join("sample_logs", "process.log")
DEFAULT_FIREWALL_LOG = os.path.join("sample_logs", "firewall.log")
DEFAULT_PERSISTENCE_DIR = os.path.join("sample_logs", "systemd", "etc_systemd_system")
DEFAULT_CANARY_DB = "canary.db"


def do_collect(conn, args):
    total = 0
    if os.path.exists(args.auth):
        n = ssh_collector.collect(conn, args.auth)
        print(f"[collect] ssh_collector      : {n} events from {args.auth}")
        total += n
        n = identity_collector.collect(conn, args.auth)
        print(f"[collect] identity_collector : {n} events from {args.auth}")
        total += n
    else:
        print(f"[collect] skipping auth log (not found: {args.auth})")

    if os.path.exists(args.process):
        n = process_collector.collect(conn, args.process)
        print(f"[collect] process_collector  : {n} events from {args.process}")
        total += n
    else:
        print(f"[collect] skipping process log (not found: {args.process})")

    if os.path.exists(args.firewall):
        n = network_collector.collect(conn, args.firewall)
        print(f"[collect] network_collector  : {n} events from {args.firewall}")
        total += n
    else:
        print(f"[collect] skipping firewall log (not found: {args.firewall})")

    extra_dirs = [args.persistence_dir] if os.path.exists(args.persistence_dir) else None
    # scan_real_system=False keeps the bundled demo focused on the sample
    # "planted backdoor" unit file instead of also flagging every legitimate
    # systemd generator already present on this machine. Set it to True
    # (or pass --scan-real-system) on an actual host you want to audit.
    n = persistence_collector.collect(conn, extra_dirs=extra_dirs,
                                       scan_real_system=args.scan_real_system)
    print(f"[collect] persistence_collector: {n} findings")
    total += n

    n = canary_collector.collect(conn, canary_db_path=args.canary_db)
    print(f"[collect] canary_collector    : {n} events from {args.canary_db}")
    total += n

    print(f"[collect] total events ingested: {total}")
    return total


def do_analyze(conn):
    results = rules.run_all(conn)
    total = sum(results.values())
    print("[analyze] rule results:")
    for rule_name, n in results.items():
        marker = " <-- fired" if n else ""
        print(f"    {rule_name:35s}: {n}{marker}")
    print(f"[analyze] total alerts raised: {total}")
    return total


def do_report(conn, out_path):
    path = report.generate(conn, out_path)
    print(f"[report] dashboard written to {path}")
    alerts = all_alerts(conn)
    if alerts:
        print("\n[report] alert summary:")
        for a in alerts:
            print(f"    [{a['severity'].upper():8s}] {a['rule']}: {a['description']}")
    return path


def main():
    parser = argparse.ArgumentParser(description="Mini-SIEM")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p):
        p.add_argument("--db", default="siem.db")
        p.add_argument("--auth", default=DEFAULT_AUTH_LOG)
        p.add_argument("--process", default=DEFAULT_PROCESS_LOG)
        p.add_argument("--firewall", default=DEFAULT_FIREWALL_LOG)
        p.add_argument("--persistence-dir", default=DEFAULT_PERSISTENCE_DIR)
        p.add_argument("--canary-db", default=DEFAULT_CANARY_DB)
        p.add_argument("--report-out", default="dashboard.html")
        p.add_argument("--scan-real-system", action="store_true",
                        help="Also scan real /etc,/usr/lib systemd dirs on this machine "
                             "(off by default so the bundled demo stays readable)")

    add_common(sub.add_parser("run", help="collect + analyze + report"))
    add_common(sub.add_parser("collect", help="only ingest logs into events table"))
    sub.add_parser("analyze", help="only run rules against existing events").add_argument("--db", default="siem.db")
    sub.add_parser("report", help="only regenerate dashboard.html").add_argument("--db", default="siem.db")

    args = parser.parse_args()

    conn = get_conn(getattr(args, "db", "siem.db"))
    init_db(conn)

    if args.command == "run":
        reset_db(conn)
        do_collect(conn, args)
        do_analyze(conn)
        do_report(conn, args.report_out)
    elif args.command == "collect":
        do_collect(conn, args)
    elif args.command == "analyze":
        do_analyze(conn)
    elif args.command == "report":
        do_report(conn, getattr(args, "report_out", "dashboard.html"))


if __name__ == "__main__":
    main()
