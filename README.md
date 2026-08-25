# HIDS — Host Intrusion Detection System

A Bash-based Host Intrusion Detection System (HIDS) built with native Linux tools. No third-party software required. Designed to monitor, detect, and report suspicious activity on a Linux system across five key areas: system health, user activity, process and network auditing, file integrity, and alerting.

---

## Table of Contents

1. [What It Does](#what-it-does)
2. [Requirements](#requirements)
3. [Installation & Deployment](#installation--deployment)
4. [Running the Tool](#running-the-tool)
5. [Automating Execution](#automating-execution)
6. [Modules Overview](#modules-overview)
7. [Interpreting the Output](#interpreting-the-output)
8. [Alert Log](#alert-log)
9. [Customising Thresholds](#customising-thresholds)
10. [Baseline & Deviation Detection](#baseline--deviation-detection)
11. [Project Structure](#project-structure)
12. [Team](#team)

---

## What It Does

This HIDS continuously checks the state of your Linux machine and flags anything that looks suspicious. It covers five monitoring areas:

| Module | What it watches |
|---|---|
| **System Health** | CPU, memory, disk usage — are resources under abnormal stress? |
| **User Activity** | Who is logged in, recent logins, failed login attempts, unexpected accounts |
| **Process & Network Audit** | Running processes with suspicious characteristics, open ports, active connections |
| **File Integrity** | Changes to critical system files, dangerous permission settings, recent modifications |
| **Alerting** | Timestamped, severity-labelled alerts written to a persistent log file |

---

## Requirements

- A Linux system (tested on Ubuntu/Debian)
- Bash 4.0 or later
- Standard Linux utilities: `awk`, `grep`, `ps`, `ss` (or `netstat`), `find`, `stat`, `last`, `who`, `df`, `free`, `md5sum`
- `cron` or `systemd` (for automated scheduling)
- Root or `sudo` privileges for full coverage (some checks require elevated permissions)

---

## Installation & Deployment

```bash
# 1. Clone the repository
git clone https://github.com/MustafaS14/HDIS-Project-BeCode.git
cd HDIS-Project-BeCode

# 2. Make all scripts executable
chmod +x hids.sh
chmod +x modules/*.sh   # if using modular layout

# 3. (Optional) Create the baseline on first run — see section below
sudo ./hids.sh --baseline
```

---

## Running the Tool

### Single run (manual)

```bash
sudo ./hids.sh
```

### Run a specific module only

```bash
sudo ./hids.sh --module health
sudo ./hids.sh --module users
sudo ./hids.sh --module processes
sudo ./hids.sh --module files
```

### Generate a summary report

```bash
sudo ./hids.sh --report
```

---

## Automating Execution

The tool is designed to run without manual intervention. Two approaches are supported:

### Using cron

```bash
# Edit the root crontab
sudo crontab -e

# Run the HIDS every 15 minutes
*/15 * * * * /path/to/HDIS-Project-BeCode/hids.sh >> /var/log/hids/cron.log 2>&1
```

### Using systemd timer

Create `/etc/systemd/system/hids.service` and `/etc/systemd/system/hids.timer`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now hids.timer
```

---

## Modules Overview

### Module 1 — System Health

Checks CPU usage, memory consumption, and disk usage against configurable thresholds. If any metric exceeds its threshold, an alert is raised with the current value.

**Example output:**
```
[OK]   CPU usage: 12%
[WARN] Memory usage: 87% (threshold: 80%)
[OK]   Disk usage (/): 54%
```

### Module 2 — User Activity

Lists currently logged-in users, recent login history, failed authentication attempts (from `/var/log/auth.log`), and checks for unexpected user accounts or UID 0 accounts other than root.

**Example output:**
```
[INFO] Currently logged in: mustafa (pts/0, 10.0.0.5)
[ALERT] 14 failed login attempts for root in the last hour
[ALERT] Unexpected UID 0 account detected: ghost
```

### Module 3 — Process & Network Audit

Lists all running processes and flags those that:
- Run from `/tmp`, `/dev/shm`, or other unusual locations
- Are owned by unexpected users
- Consume abnormally high CPU or memory

Also lists all listening ports and active connections, flagging any that are unexpected.

**Example output:**
```
[OK]   Listening ports: 22 (ssh), 80 (nginx)
[ALERT] Process running from /tmp: pid=4821 cmd=./backdoor user=www-data
[ALERT] Unexpected listening port: 4444
```

### Module 4 — File Integrity

On first run (or when `--baseline` is passed), records MD5 checksums of critical files (e.g. `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`). On subsequent runs, compares current checksums against the baseline and alerts on any mismatch.

Also checks for:
- World-writable files in sensitive directories
- SUID/SGID binaries not in the known-good whitelist
- Files modified in the last N minutes in sensitive paths

**Example output:**
```
[OK]   /etc/passwd — checksum unchanged
[ALERT] /etc/sudoers — checksum CHANGED (baseline mismatch)
[ALERT] New SUID binary found: /usr/local/bin/suspicious
```

### Module 5 — Alerting

All alerts from all modules are written to a persistent log file with a timestamp and severity level. The log is append-only and survives reboots.

---

## Interpreting the Output

Each line of output is prefixed with a status tag:

| Tag | Meaning |
|---|---|
| `[OK]` | Check passed — value is within normal range |
| `[INFO]` | Informational — no action required |
| `[WARN]` | Warning — investigate when convenient |
| `[ALERT]` | Alert — something unusual was detected, investigate promptly |
| `[CRITICAL]` | Critical — immediate action recommended |

Terminal output is colour-coded: green for OK, yellow for WARN, red for ALERT/CRITICAL.

---

## Alert Log

All alerts are appended to a persistent log file (default: `/var/log/hids/alerts.log`).

**Log format:**
```
2025-06-01T14:32:10 [ALERT] [users] 14 failed login attempts for root in the last hour
2025-06-01T14:32:11 [CRITICAL] [files] /etc/sudoers checksum mismatch — file may have been tampered with
```

Each entry contains:
- ISO 8601 timestamp
- Severity level
- Module that raised the alert
- Human-readable description

To follow the log in real time:
```bash
tail -f /var/log/hids/alerts.log
```

---

## Customising Thresholds

Thresholds are defined in `config.conf` in the root of the repository. Edit this file to adapt the tool to your environment without modifying any script.

```bash
# config.conf — HIDS configuration

# System Health thresholds (percentages)
CPU_THRESHOLD=80
MEMORY_THRESHOLD=80
DISK_THRESHOLD=90

# User Activity
MAX_FAILED_LOGINS=5          # Alert if more than this many failed logins in the last hour
ALLOWED_LOGIN_HOURS="06-22"  # Alert on logins outside these hours (24h format)

# File Integrity
BASELINE_FILE="/var/lib/hids/baseline.md5"
CRITICAL_FILES="/etc/passwd /etc/shadow /etc/sudoers /etc/hosts /etc/crontab"
RECENT_FILE_MINUTES=60       # Alert on files modified in the last N minutes in sensitive paths

# Alerting
LOG_FILE="/var/log/hids/alerts.log"
LOG_LEVEL="WARN"             # Minimum severity to log: INFO | WARN | ALERT | CRITICAL
```

After editing `config.conf`, no restart or reload is needed — the tool reads it on every run.

---

## Baseline & Deviation Detection

On the first run, pass `--baseline` to snapshot the current state of the machine:

```bash
sudo ./hids.sh --baseline
```

This records:
- MD5 checksums of all files listed in `CRITICAL_FILES`
- The list of SUID/SGID binaries currently on the system
- Currently listening ports

On every subsequent run, the tool compares the live state against this baseline and alerts on any deviation.

To reset the baseline (e.g. after a planned system change):

```bash
sudo ./hids.sh --baseline --force
```

---

## Project Structure

```
HDIS-Project-BeCode/
├── hids.sh              # Main entry point
├── config.conf          # Configurable thresholds and paths
├── modules/
│   ├── health.sh        # Module 1 — System Health
│   ├── users.sh         # Module 2 — User Activity
│   ├── processes.sh     # Module 3 — Process & Network Audit
│   ├── files.sh         # Module 4 — File Integrity
│   └── alerting.sh      # Module 5 — Alerting
├── research.md          # Research document (completed before coding)
└── README.md            # This file
```

---

## Team

Built by a team of three as part of the BeCode Linux Capstone Project.

> *"The threat is already inside. Your job is to find it before it finds you."*

