# Host Intrusion Detection System (HIDS) Bash Project

## Project Overview
This project is a lightweight Host Intrusion Detection System (HIDS) written in Bash for Linux. It monitors a host for suspicious changes and activity, compares the current system state against a known-good baseline, and writes security telemetry to local log files for review or forwarding to Elastic Cloud Serverless.

The goal of the project is to demonstrate how a practical HIDS can be built using only native Linux utilities and Bash, without requiring a full SIEM stack on the monitored machine.

## What This Project Does
The system continuously checks for signs of compromise or unauthorized change across several areas:

- **File Integrity Monitoring (FIM)** using `sha256sum` to detect unexpected changes to critical files
- **System health monitoring** to capture resource usage trends and abnormal conditions
- **User and account monitoring** to detect suspicious account changes or privilege-related activity
- **Process and network monitoring** to identify unusual executables, listeners, and suspicious ports
- **Audit logging** through `auditd` to provide security-relevant system events
- **One-minute cron scanning** with threshold-based email alerts that avoid duplicate inbox flooding
- **Log shipping** to send collected telemetry to **Elastic Cloud Serverless** for dashboarding and analysis

In short, the project helps answer: **What changed on the system, when did it change, and does that change look suspicious?**

## Architecture & Components
The solution is organized around a master Bash script and several supporting components:

- **`HIDS.sh`**
  - Main entrypoint for the project
  - Runs baseline collection, monitoring routines, report generation, and optional shipping tasks

- **Monitoring modules**
  - **File Integrity Monitoring**: hashes important files with `sha256sum` and compares results against the baseline
  - **Health monitoring**: records key system health indicators such as CPU, memory, and load
  - **User monitoring**: checks for account and privilege-related changes
  - **Process / network monitoring**: detects suspicious processes and open listeners
  - **Audit logging**: uses `auditd` on Ubuntu to capture security-relevant system events

- **Configuration files**
  - `config/hids.conf` holds thresholds, whitelists, and tuning options

- **Rules and alert content**
  - `lib/rules.sh` defines rule IDs, severity, impact, and recommended response text

- **Logs and telemetry output**
  - `.hids/hids.log` stores the active JSONL alert log used by cron and email reports
  - `.hids/summary.txt` stores the human-readable report when generated
  - `.hids/email_last_sent_id` stores the newest alert ID already emailed by the one-minute scan

- **Optional forwarders/integration scripts**
  - `elk_ship.sh` ships JSONL telemetry to Elastic Cloud Serverless
  - `send_email_report.sh` can send reports by email if configured
  - `simulate_attack.sh` provides a safe demo sequence for showing detections

## Prerequisites & Environment
This project is intended to run on a Linux host, specifically an **Ubuntu virtual machine in VirtualBox** for the capstone demo.

### Required on the monitored machine
- Ubuntu Linux VM
- Bash
- Standard Linux command-line utilities
- `openssh-server`
- `auditd`
- Tools commonly used by the monitoring scripts such as `sha256sum`, `ps`, `ss`, `who`, `last`, `lastb`, `lastlog`, `find`, `awk`, `sed`, and `grep`

### Recommended on the host machine
- VirtualBox installed
- A network configuration that allows the VM to reach the internet and/or the Elastic Cloud Serverless endpoint
- Browser access for viewing the Elastic dashboard

## Installation & Setup Instructions
### 1. Clone the repository
```bash
git clone https://github.com/MustafaS14/HDIS-Project-BeCode.git
cd HDIS-Project-BeCode
```

### 2. Configure the VM network
Choose one of the following depending on your demo environment:

- **Bridged Adapter**: gives the VM its own network presence on the LAN
- **NAT**: simpler for internet access if you only need outbound connectivity

### 3. Install required packages on Ubuntu
```bash
sudo apt update
sudo apt install -y openssh-server auditd curl
```

### 4. Enable required services
```bash
sudo systemctl enable ssh
sudo systemctl start ssh

sudo systemctl enable auditd
sudo systemctl start auditd
```

### 5. Review configuration
Edit the main configuration file as needed:
```bash
config/hids.conf
```

Adjust thresholds, monitored files, allowed ports, and other whitelist values before baseline creation.

### 6. Configure email alerts
Create a private local email configuration file. Do not commit this file.

```bash
cp email_config.env.example email_config.env
nano email_config.env
```

For Gmail SMTP, use a Google App Password for `SMTP_PASS`. If Google displays it in groups, remove the spaces before saving it:

```bash
export EMAIL_TO="recipient@example.com"
export SMTP_USER="sender@gmail.com"
export SMTP_PASS="abcdefghijklmnop"
export SMTP_SERVER="smtp.gmail.com:587"
```

Check that the VM loads the value without printing the secret:

```bash
sudo bash -c 'cd /home/vboxuser/HDIS-Project-BeCode && set -a && . ./email_config.env && set +a && echo "SMTP_PASS length=${#SMTP_PASS}"'
```

### 7. Create the baseline
Run the baseline step before starting monitoring:
```bash
./HIDS.sh --baseline
```

### 8. Install the one-minute Linux VM scan
Install auditd rules for recon-command and HIDS-log tamper monitoring, then install the one-minute cron scan:

```bash
sudo ./HIDS.sh --install-audit-rules
sudo ./HIDS.sh --install-cron
```

Verify the cron entry:

```bash
sudo cat /etc/cron.d/hids-monitor
```

Watch cron output:

```bash
tail -f .hids/cron.log
```

## Usage & Execution
### Main commands
- `./HIDS.sh --baseline`
  Create baselines for monitored files, users, and listeners.

- `./HIDS.sh --once`  
  Run the fast monitoring checks once and write alerts to `.hids/hids.log`.

- `./HIDS.sh --full`  
  Run all checks, including more expensive inventory-style scans such as SUID/SGID discovery.

- `./HIDS.sh --report`  
  Run the monitoring checks and generate a short summary report.

- `./HIDS.sh --email-report`  
  Run the checks and send the report by email if `send_email_report.sh` is available.

- `./HIDS.sh --ship-elk`  
  Run the checks and ship alerts to Elastic Cloud Serverless using the log forwarder.

- `./HIDS.sh --minute-scan`  
  Run one scan every minute when installed by cron, send email only when new alert IDs meet the threshold, and ship newly recorded events to Elasticsearch when `ELASTIC_URL` and `ELASTIC_API_KEY` are configured.

- `./HIDS.sh --install-cron`  
  On the Linux VM, install a cron entry that runs `./HIDS.sh --minute-scan` every minute. Repeated identical alerts keep their original ID and timestamp, so unchanged findings do not flood the email inbox.

- `./HIDS.sh --migrate-log`  
  Add alert IDs and hash-chain fields to existing `.hids/hids.log` entries.

- `./HIDS.sh --verify-log`  
  Verify that alert IDs are still strictly increasing and that the alert hash chain has not been changed.

### Triggering individual modules
If your implementation exposes module-specific entrypoints, you can run them directly for testing or evaluation. Typical examples include:

- file integrity checks
- health checks
- user/account checks
- process/network checks
- audit log review

Use the master script as the recommended entrypoint for normal operation.

## Dashboard & SIEM Integration
Security telemetry is stored locally in structured log form and can be forwarded to Elastic Cloud Serverless for visualization.

### Local log format
The active runtime writes one JSON object per line in `.hids/hids.log`.

Active `.hids/hids.log` entries include:
- `id`
- `prev_hash`
- `event_hash`
- `timestamp`
- `severity`
- `module`
- `message`

Some module-based or forwarded alert formats may also include extra fields such as:
- `rule`
- `host`
- `evidence`
- `impact`
- `action`

On Linux, HIDS hardens the local `.hids/hids.log` file with restrictive permissions. When run as root and when the filesystem supports it, HIDS also applies append-only protection with `chattr +a`. Each alert includes a hash of its ID, timestamp, severity, module, message, and previous alert hash, so changing an old ID or timestamp breaks `./HIDS.sh --verify-log`. Running `sudo ./HIDS.sh --install-audit-rules` also adds an auditd watch for HIDS log write and attribute changes under the `hids_log_integrity` key.

Alert IDs start at `000001` for readability and continue upward without a six-digit limit. After `999999`, the next ID is `1000000`.

If an existing log was created before IDs were added, migrate it once:

```bash
sudo ./HIDS.sh --migrate-log
./HIDS.sh --verify-log
```

If the log is already append-only, temporarily unlock it for migration:

```bash
sudo chattr -a .hids/hids.log
sudo ./HIDS.sh --migrate-log
sudo chattr +a .hids/hids.log
```

### Email alert behavior
The one-minute scan sends email only when newly observed alert IDs meet one of these thresholds:

- at least 1 new `HIGH` alert
- at least 5 new `MEDIUM` alerts

The email reporter stores the newest successfully emailed alert ID in `.hids/email_last_sent_id`. If the same alert IDs are seen again, no duplicate email is sent. Email rows show the alert ID in bold at the end of the `Details` text under the `What Happened` section.

Test email manually with the same environment-loading style used by cron:

```bash
sudo bash -c 'cd /home/vboxuser/HDIS-Project-BeCode && set -a && . ./email_config.env && set +a && ./send_email_report.sh --scheduled 30'
```

### Elastic integration flow
1. The monitoring script generates JSONL alerts.
2. The forwarder reads new log entries.
3. Alerts are shipped to **Elastic Cloud Serverless**.
4. Dashboards in Kibana can then visualize trends, repeated alerts, and high-severity findings.

### Example Elastic setup
```bash
export ELASTIC_URL="https://..."
export ELASTIC_API_KEY="..."
export ELASTIC_INDEX="hids-alerts"
```

Then run:
```bash
./elk_ship.sh --once
# or
./HIDS.sh --ship-elk
```

## Project Structure
A typical repository layout is shown below:

```text
HDIS-Project-BeCode/
├── README.md
├── research.md
├── HIDS.sh
├── simulate_attack.sh
├── elk_ship.sh
├── send_email_report.sh
├── config/
│   └── hids.conf
├── lib/
│   ├── alert.sh
│   ├── config.sh
│   ├── rules.sh
│   └── util.sh
├── modules/
│   ├── fim.sh
│   ├── health.sh
│   ├── procnet.sh
│   ├── report.sh
│   └── users.sh
└── .hids/
    ├── hids.log
    ├── summary.txt
    └── email_last_sent_id
```

## Evaluation Goals
This project demonstrates that a Bash-only HIDS can:

- create a baseline of trusted system state
- detect deviations from that baseline
- record meaningful security telemetry
- support automated execution with cron
- integrate with Elastic Cloud Serverless for dashboarding

## Demo Scenario
The demo script can simulate suspicious activity so the project can be shown safely without requiring a real compromise. The simulated activity is intended to trigger file integrity or related alerts and demonstrate the response workflow end to end.

## Troubleshooting & Operational Notes
- If `ss`, `last`, or `auditd` are missing, verify the required packages are installed.
- If the script cannot read certain system files, run it with the permissions expected by the project.
- If no alerts appear, confirm that the baseline was created first and that the monitored files or services have actually changed.
- If Elastic ingestion fails, verify the API key, endpoint URL, and index name.
- If cron-based execution does not run on the Linux VM, check that the cron service is enabled and that `./HIDS.sh --install-cron` installed the `* * * * *` entry correctly.
- If email fails with `curl: (67) Login denied`, Gmail rejected the SMTP credentials. Generate a new Gmail App Password for the same account in `SMTP_USER` and save it without spaces in `email_config.env`.
- If `.hids/hids.log` does not show `id`, `prev_hash`, and `event_hash`, pull the latest code and run `sudo ./HIDS.sh --migrate-log` on the VM.

## Exit Codes
- `0`: clean or INFO-only
- `1`: LOW/MEDIUM alerts present
- `2`: HIGH alerts present
- `3`: CRITICAL alerts present

## Summary
This HIDS project monitors a Linux system for suspicious changes in files, users, processes, network listeners, and system health. It uses a baseline-driven approach, writes structured alerts to local logs, and can forward telemetry to Elastic Cloud Serverless for visual analysis and reporting.
