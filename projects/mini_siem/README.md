# Mini-SIEM (Day 13 — 30 Days 30 Projects)

A small, dependency-free SIEM built by turning your earlier day-projects
into **collectors** that feed one normalized event store, on top of which
sits a **rule engine** and a one-page **HTML dashboard**.

```
sample logs  ─▶  collectors  ─▶  events table  ─▶  rule engine  ─▶  alerts table  ─▶  dashboard.html
(auth.log,       (ssh, identity,   (SQLite,           (rules.py)        (SQLite)
 process.log,     process,         siem.db)
 firewall.log,    network,
 canary.db,       persistence,
 systemd dirs)    canary)
```

## Quick start

```bash
cd mini_siem
python3 run_siem.py run
```

That's it — no config needed. It will:
1. Parse the bundled sample logs in `sample_logs/`
2. Ingest everything into `siem.db` as normalized events
3. Run all 10 detection rules against those events
4. Write `dashboard.html` — open it in a browser
5. Print a plain-text alert summary to the console

Want to see the canary-token rule fire too?
```bash
python3 seed_demo_canary.py   # writes one fake trigger into canary.db
python3 run_siem.py run
```

Other commands:
```bash
python3 run_siem.py collect   # only ingest logs, don't run rules
python3 run_siem.py analyze   # only run rules against the existing DB
python3 run_siem.py report    # only rebuild dashboard.html
```

Point it at real logs instead of the sample ones:
```bash
python3 run_siem.py run --auth /var/log/auth.log --process /path/to/process.log \
    --firewall /path/to/firewall.log --scan-real-system
```

## Why it's built this way

A real SIEM's whole value is turning a pile of *differently shaped* logs
into *one shape* so you can write detection logic once instead of once
per log source. So the project has three strict layers, and nothing skips
a layer:

1. **Collectors** (`collectors/*.py`) — each one understands ONE raw log
   format and calls `siem_core.log_event()` to store it in the common
   `events` table. Collectors never decide what's "suspicious" — they
   just normalize.
2. **Rule engine** (`rules.py`) — reads only from the `events` table
   (never raw logs) and decides what's alert-worthy, writing to the
   `alerts` table via `siem_core.log_alert()`.
3. **Reporting** (`report.py`) — reads only from `events`/`alerts` and
   renders `dashboard.html`. Doesn't know or care where the data came from.

This split is exactly why you can add a brand-new log source later (say,
Windows Event Logs) by writing one new collector file — zero changes
needed to rules.py or report.py.

## How your existing scripts became collectors

| Day | Script | Role in the mini-SIEM |
|---|---|---|
| 09 | `ssh_bruteforce_detect.py` | Became `collectors/ssh_collector.py`. Same regex for `Failed password`, plus a **new** regex for `Accepted password` (needed so the brute-force rule can tell "attempts" apart from "attempts that actually got in"). Detection logic and firewall-blocking were deliberately **removed** from the collector — a collector's only job is parsing; the rule engine decides what's bad, and a future "responder" module would be the only thing allowed to touch the firewall. |
| 10 | `Systemd_Persistence_Scanner.py` | Split into `collectors/persistence_scanner_lib.py` (same detection logic, but functions **return** findings instead of `print()`-ing them) and `collectors/persistence_collector.py` (calls the lib, turns each finding into a normalized event). This is a *periodic* collector, not a log-tailer — run it on a schedule (cron every hour, e.g.) rather than continuously. |
| 12 | `canary.py` | Not modified at all. `collectors/canary_collector.py` just opens the `canary.db` that `canary.py` already writes to when a bait file is opened, and imports each row as a `canary_triggered` event. This is the cleanest integration in the project: two independent tools, one shared database. |

## New collectors (no Day-X script covered these signal types)

| Collector | Log format it reads | Rules it feeds |
|---|---|---|
| `identity_collector.py` | Same `auth.log`, but the `useradd`/`usermod` and firewall/log-tamper lines | Off-hours account creation, privilege group modification, log/security tampering |
| `process_collector.py` | A simple space-delimited process-exec log (`parent=... child=... cmd="..."`) — the shape you'd get from `auditd` execve rules or an EDR agent | Suspicious child process, LOLBins, encoded execution |
| `network_collector.py` | An iptables-style `IPTABLES-DROP` firewall log | Port scanning / reconnaissance |

`network_collector.py` intentionally does **not** use `trafficanalyser.py`'s
scapy/live-sniffing approach, to keep this runnable anywhere without root
or a physical interface. But the fields it needs (source IP, destination
port, SYN flag) are exactly what `trafficanalyser.py`'s `analyze_packet()`
already extracts — if you want live traffic instead of a firewall log, call
`log_event(..., event_type="firewall_drop")` from inside that function
instead of `print()`.

## The 10 detection rules

**Authentication & Identity**
1. **Brute-Force Login Success** — ≥5 failed logins for one user, followed
   by a success for that *same* user, all within 5 minutes. (Requiring the
   eventual success is what tells you the attack worked, not just that
   someone mistyped a password a few times.)
2. **Account Creation Outside Business Hours** — new user created before
   06:00, after 20:00, or on a weekend.
3. **Privilege Group Modification** — a user added to `sudo`, `wheel`,
   `admin`, `administrators`, or `domain admins`.

**Endpoint & Process Execution**
4. **Suspicious Child Process Spawning** — a web server or office app
   (`nginx`, `httpd`, `winword.exe`, …) spawning a shell.
5. **Living-off-the-Land Binaries (LOLBins)** — `certutil -urlcache -split -f`,
   `bitsadmin /transfer`, or `curl`/`wget` piped straight into `sh`.
6. **Encoded/Obfuscated Command Execution** — `-EncodedCommand`, `-enc`, or
   `base64 -d | sh` patterns.
7. **Security Service / Log Tampering** — firewall disabled, logs cleared,
   or a security service (e.g. `auditd`) stopped.

**Network & Perimeter**
8. **Port Scanning / Reconnaissance** — ≥20 distinct destination ports
   dropped from one source IP within 60 seconds.

**Deception & Persistence** *(added beyond the original list, since Day 10
and Day 12 already gave us the data for them)*
9. **Canary Token Triggered** — any hit on a canary.py token. Always
   critical — there's no legitimate reason for this to fire.
10. **Systemd Persistence Indicator** — HIGH/CRITICAL findings from the
    Day 10 scanner (temp-directory `ExecStart=`, suspicious commands,
    unexpected generator scripts).

### Rules from your list that were intentionally left out (for now)

- **Beaconing / periodic C2 connections** and **large outbound data
  transfer (exfiltration)** both need a *baseline* of normal traffic volume
  and timing per host before "unusual" means anything — that's a
  meaningfully bigger project (you'd want to track a rolling per-host
  average, e.g. in a `baselines` table) rather than a single pattern-match
  rule. Left as a natural "Day 14" follow-up once `network_collector.py`
  is ingesting real flow data instead of firewall-drop logs.

Both are easy to bolt on later: add a `network_flow` event type (bytes
transferred, interval between connections) from a NetFlow/proxy log, and
two new rule functions that compare against a stored per-host baseline.

## How the rest of your toolkit fits in (even though they're not collectors)

Not every Day-X script belongs in an automated pipeline — some are
**analyst tools** you reach for *after* the SIEM raises an alert, not
things that should run unattended. Wiring them in as collectors would
have made them worse at their actual job. Here's where each one earns its
keep in a real investigation:

- **`hash_carck.py` (Day 04)** — An alert fires because a canary `.docx`
  was password-protected and someone finally opened it? If you recover a
  password hash from a captured credential or a cracked archive during
  the investigation, this is the tool you reach for. Doesn't belong in
  the automated pipeline (cracking is slow, and running it against every
  hash you see would just burn CPU for no reason) but it's exactly the
  tool that turns a SIEM alert into an actual answer.
- **`metadata_extractor.py` (Day 05)** — A `suspicious_child_process`
  alert says `winword.exe` spawned `cmd.exe`. Pull the `.docx` that
  triggered it and run this to check the `author`/`last_modified_by`
  fields and creation timestamp — often the fastest way to see whether a
  "client invoice" was actually authored days before it was supposedly
  sent to you.
- **`dns_lookup.py` (Day 03)** — A `lolbin_exec` or `encoded_exec` alert
  contains a raw IP or domain (like `45.33.12.9` in the sample data).
  Point this at it, or at a suspicious domain from `dns_exfiltration`-style
  findings, to see its DNS footprint (any PTR record, mail exchangers,
  odd TXT records) before you decide whether it's worth blocking.
- **`port_scanner.py` (Day 02)** — Once `rule_port_scan` tells you IP
  `45.33.12.9` was scanning you, you can point this at *that* attacker's
  own IP (from a sanctioned red-team box) to see what it's running, or
  use it defensively against your own hosts to confirm nothing new opened
  up after an incident.
- **`trafficanalyser.py` (Day-extra)** — This is the tool you'd reach for
  to actually confirm a `port_scan` or `dns_exfiltration` alert against a
  full pcap taken during the incident window, since it does deeper
  per-packet analysis (ARP spoofing, DNS tunneling patterns, GeoIP on
  destination IPs) than the lightweight firewall-log collector does.
- **`ceasar2.py`, `base64_v2.py`, `hexcoder.py` (Day 01)** — Genuinely
  just utility encoders/decoders. If an alert's raw payload turns out to
  be base64 or hex-obfuscated (very common in the `encoded_exec` rule's
  target pattern), these are your by-hand decode tools during triage.
  There's no "SIEM integration" story here beyond that — and that's fine;
  not every script from a security fundamentals course needs to become
  automated tooling.

## Data model

**`events`** — one normalized row per raw log line/finding:
`id, timestamp, source, event_type, host, user, src_ip, severity, message, raw`

**`alerts`** — one row per rule firing:
`id, timestamp, rule, severity, description, src_ip, user, event_ids (JSON)`

`event_ids` on an alert links back to the exact `events` rows that caused
it — the "show your work" trail a real analyst needs to investigate
instead of just trusting the alert text.

## Known simplifications (this is a "mini" SIEM on purpose)

- **No incremental ingestion.** `run` wipes `siem.db` and reprocesses the
  full sample logs every time, rather than tracking a file offset like
  `logstash`/`filebeat` would. Fine for a demo; for a live host you'd tail
  files (see Day 09's original approach) and only ingest new lines.
- **No response/blocking module.** The original `ssh_bruteforce_detect.py`
  could call `ufw`/`iptables` directly. That's intentionally not wired in
  here — a SIEM should raise alerts; whether and how to auto-respond is a
  separate, higher-stakes decision worth its own module and its own
  safeguards.
- **Single-host demo.** `host` is just a string field per event; there's
  no multi-host agent/collector architecture. Good enough to prove the
  rule logic, not meant to be pointed at a fleet as-is.

## File map

```
mini_siem/
├── run_siem.py                  # CLI entry point
├── siem_core.py                 # SQLite schema + log_event()/log_alert()
├── rules.py                     # the 10 detection rules
├── report.py                    # builds dashboard.html
├── seed_demo_canary.py          # optional: fakes one canary trigger for the demo
├── collectors/
│   ├── ssh_collector.py         # Day 09, adapted
│   ├── identity_collector.py    # new: useradd/usermod/tamper lines
│   ├── process_collector.py     # new: LOLBins/encoded exec/child process
│   ├── network_collector.py     # new: firewall-log port scan detection
│   ├── persistence_collector.py # wraps persistence_scanner_lib
│   ├── persistence_scanner_lib.py # Day 10 logic, refactored to return findings
│   └── canary_collector.py      # reads Day 12's canary.db directly
└── sample_logs/
    ├── auth.log                 # SSH + useradd/usermod + tamper lines
    ├── process.log              # sample process executions
    ├── firewall.log             # sample port scan
    └── systemd/etc_systemd_system/updater.service   # planted fake backdoor unit
```
