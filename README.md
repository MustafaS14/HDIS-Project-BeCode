# HIDS Bash Project

This project is a lightweight host-based intrusion detection system (HIDS) written in bash. It monitors the host for common signs of tampering, malicious activity, and persistence, then writes alerts to a persistent log file with timestamps and severity levels.

It is intentionally built with native Linux command-line tools and Bash only (no third-party software dependencies).

## What it checks
The tool covers comprehensive monitoring modules:

- **File integrity monitoring** (HIGH severity on tampering or deletion)
- **Process activity monitoring** (MEDIUM/HIGH severity on suspicious processes)
- **Network listener & unusual port monitoring** (HIGH severity on non-standard ports)
- **C2 Beaconing detection** (HIGH severity on repeated periodic outbound signals)
- **Brute force detection** (HIGH severity on failed login spikes followed by successful login)
- **User account monitoring** (MEDIUM severity on new/modified accounts)
- **Privileged binary monitoring** (HIGH severity on new SUID/SGID binaries)

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
./HIDS.sh --ship-elk
```

This will create the initial baseline and run a full scan.
The ship command runs a scan and sends newly generated events to Elasticsearch in one step.

## Demo mode
To trigger a simulated malicious activity and generate a log alert, run:

```bash
./HIDS.sh --demo
```

The demo writes to a monitored file to trigger an integrity alert using only native shell operations.

## Automatic scheduling (Hourly)
To install a recurring scheduled check that runs hourly, run:

```bash
sudo ./HIDS.sh --install-cron
```

On systems without root permissions, the script attempts to add a user crontab entry instead.

## Email Security Reports
You can receive automated security reports delivered to your email inbox hourly.

1. Set your SMTP environment variables:
```bash
export EMAIL_TO="your.email@example.com"
export SMTP_USER="your.email@example.com"
export SMTP_PASS="your-app-password"  # e.g., Gmail App Password
export SMTP_SERVER="smtp.gmail.com:587"
```

2. Generate an instant report on-demand:
```bash
./HIDS.sh --email-report
```

3. To include automated email reporting in your hourly cron job, edit your crontab (`crontab -e`):
```bash
0 * * * * export EMAIL_TO="your.email@example.com" SMTP_USER="your.email@example.com" SMTP_PASS="your-app-password"; /bin/bash /path/to/HIDS_project/HIDS.sh --ship-elk >/dev/null 2>&1
```

## Output files
The project stores working files in the .hids directory:

- .hids/hids.log - persistent JSON alert log, ready for ELK/Filebeat ingestion
- .hids/summary.txt - summary report generated after each run
- .hids/baseline/ - saved baseline snapshots

## ELK compatibility
The log file uses JSON lines rather than plain text so Elasticsearch or Logstash can parse fields like timestamp, severity, module, and message directly.

Example line:

```json
{"timestamp":"2026-08-26 16:55:36 CEST","severity":"HIGH","module":"file_integrity","message":"Integrity change detected for /path/to/file"}
```

## Connect to ELK (Elastic Security UI)
This repository now includes a native Bash shipper script (`elk_ship.sh`) that sends new HIDS log entries to Elasticsearch using the Bulk API.

1. Create an API key in Kibana:
	- Stack Management -> API Keys -> Create API key
	- Save the encoded key value (used as `ELASTIC_API_KEY`)

2. Export environment variables on the Linux host where HIDS runs:

```bash
export ELASTIC_URL="https://<your-elastic-endpoint>:443"
export ELASTIC_API_KEY="<base64-encoded-api-key>"
export ELASTIC_INDEX="hids-alerts"
```

3. Make the shipper executable and send current/new events:

```bash
chmod +x ./elk_ship.sh
./elk_ship.sh --once
```

Or use one command from the main script:

```bash
./HIDS.sh --ship-elk
```

4. Verify ingestion in Kibana:
	- Discover -> select `hids-alerts*`
	- Confirm fields like `timestamp`, `severity`, `module`, and `message`

5. Optional cron shipping every minute:

```bash
* * * * * ELASTIC_URL="https://<your-elastic-endpoint>:443" ELASTIC_API_KEY="<base64-encoded-api-key>" ELASTIC_INDEX="hids-alerts" /bin/bash /path/to/HIDS_project/elk_ship.sh --once >/dev/null 2>&1
```

6. Optional Detection rule in Elastic Security:
	- Security -> Rules -> Create new rule -> Custom query
	- Index pattern: `hids-alerts*`
	- Example KQL: `severity : "HIGH" or severity : "WARNING"`
	- This will populate the Alerts screen once matching events are indexed.

## ELK-provided snippet (reference)
The exact snippet returned by ELK has been included in this repository at `elk_snippet_from_elk.sh`.

- It has been adapted to a native Bash + curl variant.
- It uses API key authentication.
- The project's default integration path remains `elk_ship.sh`, which uses Bash + curl + API key auth and offset tracking.

## Security note
This tool is intended for educational, testing, and local monitoring use. It does not replace a full enterprise security stack or endpoint detection solution.

## License
This project is provided as a learning exercise and may be adapted for educational use.
