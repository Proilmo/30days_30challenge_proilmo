# 🛡️ Mini-SIEM — Day 13 of #30Days30Projects

Built by **Iliass Mouchrif** — Networks & Cybersecurity engineering student @ INPT, Rabat

A dependency-free mini SIEM that turns messy logs (SSH auth, account activity,
process execution, firewall drops, canary tokens, systemd persistence) into
one normalized event stream, runs 10 detection rules against it, and spits
out a dashboard you can open in any browser. Built by wiring together and
extending five earlier projects from this challenge — see [Where each rule
comes from](#-where-each-rule-comes-from) below.

```
sample logs  ─▶  collectors  ─▶  events table  ─▶  rule engine  ─▶  alerts table  ─▶  dashboard.html
```

## ⚡ Quick start

No external dependencies for the core pipeline — just Python 3 and its
standard library.

```bash
git clone <your-repo-url>
cd mini_siem
python3 run_siem.py run
open dashboard.html   # (or just double-click it)
```

Want to see the canary-token rule fire too?

```bash
python3 seed_demo_canary.py
python3 run_siem.py run
```

Point it at your own logs instead of the bundled samples:

```bash
python3 run_siem.py run \
  --auth /var/log/auth.log \
  --process /path/to/process.log \
  --firewall /path/to/firewall.log \
  --scan-real-system
```

Other commands: `collect` (ingest only), `analyze` (rules only), `report`
(rebuild the dashboard only).

## 🧠 Why it's built this way

A real SIEM earns its keep by turning *differently shaped* logs into *one
shape*, so detection logic gets written once instead of once per log
source. This project keeps that boundary strict:

1. **Collectors** (`collectors/*.py`) — each understands ONE raw log
   format and normalizes it into the shared `events` table. They never
   decide what's suspicious.
2. **Rule engine** (`rules.py`) — reads only from `events`, decides what's
   alert-worthy, writes to `alerts`. Never touches raw logs.
3. **Reporting** (`report.py`) — reads only `events`/`alerts`, renders
   `dashboard.html`. Doesn't know or care where the data came from.

Adding a new log source later (Windows Event Logs, say) means writing one
new collector file — zero changes to `rules.py` or `report.py`.

## 🔎 The 10 detection rules

| # | Rule | Category |
|---|---|---|
| 1 | Brute-Force Login Success (≥5 fails → success, same user, 5 min) | Auth & Identity |
| 2 | Account Creation Outside Business Hours | Auth & Identity |
| 3 | Privilege Group Modification (`sudo`, `wheel`, `admins`...) | Auth & Identity |
| 4 | Suspicious Child Process Spawning (web/office app → shell) | Endpoint |
| 5 | Living-off-the-Land Binaries (`certutil`, `bitsadmin`, `curl\|sh`) | Endpoint |
| 6 | Encoded / Obfuscated Command Execution | Endpoint |
| 7 | Security Service / Log Tampering | Endpoint |
| 8 | Port Scanning / Reconnaissance (≥20 ports, 1 IP, 60s) | Network |
| 9 | Canary Token Triggered | Deception |
| 10 | Systemd Persistence Indicator | Persistence |

`Beaconing/C2` and `large outbound data exfiltration` were deliberately
left out — both need a per-host traffic *baseline* before "unusual" means
anything, which is a bigger project than a single pattern-match rule.
Noted as a clear next step.

## 🧩 Where each rule comes from

| Source | Became | Notes |
|---|---|---|
| Day 09 — SSH Brute-Force Detector | `collectors/ssh_collector.py` | Kept the original regex, added a matcher for successful logins so the rule can tell "noise" from "an attacker who got in" |
| Day 10 — Systemd Persistence Scanner | `collectors/persistence_scanner_lib.py` + `persistence_collector.py` | Same detection logic, refactored to return findings instead of printing them |
| Day 12 — Canary Token Generator | `collectors/canary_collector.py` | Untouched — this collector just reads the `canary.db` that `canary.py` already writes to |
| New | `identity_collector.py`, `process_collector.py`, `network_collector.py` | Built to cover the identity, endpoint, and network rule categories the earlier days didn't touch |

Day 02–05 scripts (port scanner, hash cracker, metadata extractor, DNS
lookup) intentionally stayed **out** of the automated pipeline — they're
analyst tools you reach for *after* an alert fires, not things that should
run unattended. Full reasoning for each is in the long-form write-up.

## 🗃️ Data model

**`events`** — `id, timestamp, source, event_type, host, user, src_ip, severity, message, raw`
**`alerts`** — `id, timestamp, rule, severity, description, src_ip, user, event_ids`

Every alert keeps `event_ids` pointing back to the exact events that
triggered it — the "show your work" trail an analyst actually needs.

## 📁 Project structure

```
mini_siem/
├── run_siem.py                     # CLI entry point
├── siem_core.py                    # SQLite schema + log_event()/log_alert()
├── rules.py                        # the 10 detection rules
├── report.py                       # builds dashboard.html
├── seed_demo_canary.py             # fakes one canary trigger for the demo
├── collectors/
│   ├── ssh_collector.py
│   ├── identity_collector.py
│   ├── process_collector.py
│   ├── network_collector.py
│   ├── persistence_collector.py
│   ├── persistence_scanner_lib.py
│   └── canary_collector.py
└── sample_logs/
    ├── auth.log
    ├── process.log
    ├── firewall.log
    └── systemd/etc_systemd_system/updater.service
```

## ⚠️ Known simplifications

This is a *mini* SIEM, on purpose:
- No incremental ingestion — each `run` reprocesses full sample logs
  rather than tailing files and tracking offsets like `filebeat` would.
- No response/blocking module — a SIEM raises alerts; auto-response is a
  separate, higher-stakes decision left out on purpose.
- Single-host demo — `host` is just a string field, no fleet/agent model.

## 🎓 About this project

Part of my **#30Days30Projects** cybersecurity challenge — one small,
runnable security tool a day. Previous days covered classic ciphers,
a port scanner, a DNS enumeration tool, a hash cracker, a metadata
scraper, a CIS hardening auditor, an SSH brute-force detector, a systemd
persistence scanner, a secrets scanner, and a canary token generator.
This one ties several of them together into something closer to what a
SOC actually runs.

**Iliass Mouchrif** — Networks & Cybersecurity engineering student, INPT
Rabat · [LinkedIn](#) · iliassmouchrif2@gmail.com
