# HIDS Bash Project

This project is a lightweight host-based intrusion detection system (HIDS) written in bash. It monitors the host for common signs of tampering, malicious activity, and persistence, then writes alerts to a persistent log file with timestamps and severity levels.

It is intentionally built with native Linux command-line tools and Bash only (no third-party software dependencies).

## What it checks
The tool covers five monitoring modules:

- File integrity monitoring
- Process activity monitoring
- Network listener monitoring
- User account monitoring
- Privileged binary monitoring

## Main features
- Creates a baseline snapshot of important system state
- Detects changed files, new processes, suspicious listeners, new user accounts, and unexpected privileged binaries
- Writes alerts to .hids/hids.log with a standard timestamped format
- Can be scheduled to run automatically with cron
- Includes a simulated demo mode that triggers a real alert

## Requirements
The script is designed for Linux-based systems and expects common tools such as:

- bash
- sha256sum
- ps
- ss or netstat
- find
- getent
- cron (optional for automatic scheduling)

## Quick start
From the project directory, run:

```bash
./HIDS.sh --baseline
./HIDS.sh --once
```

This will create the initial baseline and run a full scan.

## Demo mode
To trigger a simulated malicious activity and generate a log alert, run:

```bash
./HIDS.sh --demo
```

The demo writes to a monitored file to trigger an integrity alert using only native shell operations.

## Automatic scheduling
To install a recurring scheduled check, run:

```bash
sudo ./HIDS.sh --install-cron
```

On systems without root permissions, the script attempts to add a user crontab entry instead.

## Output files
The project stores working files in the .hids directory:

- .hids/hids.log — persistent JSON alert log, ready for ELK/Filebeat ingestion
- .hids/summary.txt — summary report generated after each run
- .hids/baseline/ — saved baseline snapshots

## ELK compatibility
The log file uses JSON lines rather than plain text so Elasticsearch or Logstash can parse fields like `timestamp`, `severity`, `module`, and `message` directly.

Example line:

```json
{"timestamp":"2026-08-26 16:55:36 CEST","severity":"HIGH","module":"file_integrity","message":"Integrity change detected for /path/to/file"}
```

## Security note
This tool is intended for educational, testing, and local monitoring use. It does not replace a full enterprise security stack or endpoint detection solution.

## License
This project is provided as a learning exercise and may be adapted for educational use.
