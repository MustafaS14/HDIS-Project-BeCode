# HIDS Bash Project Research

## Objective
This project investigates how a lightweight host-based intrusion detection system can be built in bash to monitor a Linux host without requiring a full SIEM stack. The final result is a script that records a trusted baseline, checks for drift, surfaces suspicious activity, and logs alerts in a persistent file.

The implementation target is native Linux command-line tools plus Bash only, with no third-party software requirement.

## Required modules
The project covers five core monitoring categories:

1. File integrity monitoring
   - Tracks important configuration files such as /etc/passwd, /etc/hosts, /etc/ssh/sshd_config, and /etc/sudoers.
   - Uses SHA-256 checksums to compare the current state with a previously saved baseline.
   - Detects tampering, unexpected edits, and deleted files.

2. Process monitoring
   - Records the command names that are currently running.
   - Detects unusual executables that appear after the baseline was created.
   - Helps identify malware, backdoors, and persistence attempts that launch as separate processes.

3. Network monitoring
   - Reviews open listening ports using ss or netstat.
   - Alerts when a new port is opened or when a suspicious listener appears.
   - Useful for spotting reverse shells, unauthorized services, or malicious web servers.

4. User and account monitoring
   - Compares the current passwd database with the baseline.
   - Flags newly created accounts, unexpected modified accounts, and known suspicious changes.
   - Helps catch privilege escalation and account-creation actions by an attacker.

5. Privilege and persistence monitoring
   - Searches for SUID and SGID binaries.
   - Detects new privileged executables that may be abused to gain root access or maintain persistence.
   - Helps reveal attacker techniques such as setting file permissions for privilege abuse.

## Why a baseline matters
A host intrusion detection tool is more useful when it compares the current state against a known-good state instead of only checking hardcoded thresholds. This project stores a baseline in .hids/baseline and uses it for future scans. The baseline is not perfect, but it is a practical starting point for Linux monitoring.

## Automatic execution options
The project requires automatic execution without a manual trigger. Two standard approaches were considered:

- Cron jobs: best for simple recurring checks every few minutes or hours.
- Systemd timers: better for modern Linux systems that already run systemd.

Cron was chosen for this implementation because it is simple to install and works on many Linux distributions. The script includes an install_scheduler function that writes a cron entry to either /etc/cron.d/hids-monitor or a user crontab depending on permissions.

## Alerting and logging design
The alerting mechanism logs every event in a persistent file called .hids/hids.log with this structure:

timestamp|severity|module|message

This format is easy to inspect manually and can later be parsed by another script or SIEM tool. Severity values include INFO, MEDIUM, HIGH, and WARNING.

## Live demo approach
To satisfy the live demo requirement, the project includes a simulated malicious sequence:

- write to a monitored file in the project directory
- run a full HIDS scan

These actions trigger file-integrity alerts in the log and demonstrate the tool working without needing a real compromise.

## Implementation notes
- The script is intentionally bash-based and lightweight for educational use.
- It stores state under the project directory so it is portable and easy to review.
- The script is designed to be read by humans and can be expanded with more modules in the future.
- All functions are documented with a comment block explaining their purpose.

## Future improvements
The project could be extended with several nice-to-have upgrades in later versions, including:

- configurable thresholds via a config file
- JSON-formatted alert output
- colorized console output
- email notifications for critical alerts
- a baseline-aware whitelist system
- a live monitoring dashboard with refreshes and alarm summaries
