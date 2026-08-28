# HIDS Bash Project Research

## Objective
This project investigates how a lightweight host-based intrusion detection system can be built in bash to monitor a Linux host without requiring a full SIEM stack. The final result is a script that re[...]

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
A host intrusion detection tool is more useful when it compares the current state against a known-good state instead of only checking hardcoded thresholds. This project stores a baseline in .hids/base[...]

## Automatic execution options
The project requires automatic execution without a manual trigger. Two standard approaches were considered:

- Cron jobs: best for simple recurring checks every few minutes or hours.
- Systemd timers: better for modern Linux systems that already run systemd.

Cron was chosen for this implementation because it is simple to install and works on many Linux distributions. The script includes an install_scheduler function that writes a cron entry to either /etc[...]

## Alerting and logging design
The alerting mechanism logs every event in a persistent file called .hids/hids.log with this structure:

timestamp|severity|module|message

This format is easy to inspect manually and can later be parsed by another script or SIEM tool. Severity values include INFO, MEDIUM, HIGH, and WARNING.

## Live demo approach
To satisfy the live demo requirement, the project includes a simulated malicious sequence:

- write to a monitored file in the project directory


This action trigger file-integrity alerts in the log and demonstrate the tool working without needing a real compromise.

---

## Research: What Makes Professional HIDS Tools Effective

### What separates a good monitoring tool from a bad one?

Professional HIDS tools like Wazuh, OSSEC, Auditd, and Tripwire don't attempt to answer "is the machine hacked?" with a single metric. Instead, they combine multiple evidence sources by scanning relevant files and databases, normalizing findings, establishing context and baselines, comparing observations against either an established baseline or a centralized server database, and generating alerts only when evidence is meaningful—as defined by the user or the tool's developers.

---

### On system health:

**What aspects of a running Linux system indicate health or stress?**

The amount of known processes along with their usage patterns reveals system health. Linux exposes this information through both commands and files in /proc/:

- `top` – process activity and resource consumption
- `free` – memory usage (RAM)
- `smartmontools` – hard drive component status
- `sysstat` (iostat) – hard drive input/output metrics
- `lm-sensors` – component temperatures
- `ss` – network connections

**What values or thresholds warrant alerting?**

Sustained iowait above 20–30% indicates a disk or storage issue and warrants investigation with `iostat -xz 1`. The file `/proc/loadavg` provides 1-, 5-, and 15-minute load averages; if the value trends upward over 15 minutes, something is building up—a runaway process, thread leak, or I/O bottleneck.

---

### On users and activity:

**How does Linux record who has logged in, when, and from where?**

Linux maintains historical records of logins in binary files usually located in `/var/log/`:

- **utmp / wtmp** – Logs of currently logged-in users and login history. The `last` command reads this file to show login details including IP address or terminal and session duration.
- **btmp** – Failed login attempt records. The `lastb` command audits brute-force or failed access attempts.
- **Authentication Logs** (/var/log/auth.log on Ubuntu, /var/log/secure on other systems) – Real-time authentication events recorded as plain text, including timestamp, username, source IP, and success or failure status for SSH logins, sudo usage, user account switches, and PAM authentication.

**Which commands let you read these records?**

- `w` or `who` – Shows who is currently logged in, their terminal, login time, and source IP
- `last -a` – Displays login history with hostname/IP moved to the end of the line for readability
- `lastlog` – Shows the last login timestamp for all users on the system (reads from /var/log/lastlog)
- `grep "Accepted" /var/log/auth.log` – Filters specifically for successful login events

**What user activity would look suspicious on a production server?**

- Logging in and running discovery commands like `whoami`, `id`, `uname -a`, or scanning for SUID files
- Frequent usage of sudo or su by non-admin service accounts
- Modifying `/etc/crontab`, adding files to `/etc/cron.d/`, or tampering with authorized SSH keys (~/.ssh/authorized_keys)
- Clearing command history (`history -c`) or deleting shell history files, or renaming script files to mimic standard system processes

---

### On processes:

**How do you get a full picture of what is running on a system?**

Use `ps` for active processes and `top` to see all processes on the computer, including "sleeping" ones.

**What makes a process look suspicious—beyond just its name?**

Several key vectors indicate suspicious behavior:

- **Process Owner (UID)**: A system daemon (like a web server or database) running as root instead of its dedicated, low-privilege service account (e.g., www-data or mysql)
- **Execution Path & Working Directory**: Running from world-writable or temporary directories (/tmp/, /dev/shm/, /var/tmp/) instead of standard system paths (/usr/bin/, /usr/sbin/)
- **Resource Consumption**: Unusual, sudden spikes in CPU or RAM usage without associated workload, or abnormal connection counts
- **Parent-Child Hierarchy (PPID)**: A process spawned by an unexpected parent—for example, an interactive shell (bash/sh) or web service spawning a generic terminal shell
- **Command-Line Arguments**: Disguised execution names (e.g., a process named [kworker] running from a user's home directory) or hidden parameters designed to evade detection

**Where does Linux store live process information that you can read without special tools?**

Linux stores live process information as a virtual filesystem directly in `/proc/`. These files are dynamically generated in memory by the kernel whenever accessed, allowing you to read live system and process data using standard text-reading tools (cat, less, awk) without specialized utilities.

Every running process receives a unique Process ID (PID), with a corresponding directory inside `/proc/` named after that ID (e.g., `/proc/1234/`). Key files and symlinks within each process directory include:

- `/proc/[PID]/cmdline` – Command-line arguments showing exactly how the process was executed
- `/proc/[PID]/exe` – A symlink to the actual binary executable, useful for verifying legitimate paths or detecting execution from suspicious directories like /tmp
- `/proc/[PID]/status` – Detailed memory usage, process state (running, sleeping, zombie), and UID/GID
- `/proc/[PID]/fd/` – All open file descriptors, showing which files, sockets, or pipes the process has open

Beyond individual PIDs, `/proc/` also contains global metrics:

- `/proc/loadavg` – Live system load averages (1, 5, and 15 minutes) and count of running versus total processes
- `/proc/stat` – Real-time CPU and kernel statistics aggregated across all processes since boot

**How to read this using native tools:**

- View a process's command line: `cat /proc/<PID>/cmdline`
- Check the executable path: `ls -l /proc/<PID>/exe`
- Inspect status and resources: `cat /proc/<PID>/status`

---

### On the network:

**How do you see what ports a machine is listening on?**

Use `ss` to query the kernel directly for socket information:

```
sudo ss -tulpn
```

Flags:
- `-t` – Show TCP sockets
- `-u` – Show UDP sockets
- `-l` – Display only listening sockets
- `-p` – Show the process name and PID associated with the port (requires sudo)
- `-n` – Show numeric ports and IPs instead of resolving names (faster and cleaner)

**How do you see active connections and which process is responsible?**

Commands like `ss`, netstat, and `lsof` all display PID, process name, protocols, user, connection type, and ports in different formats.

**What kind of network activity would be a red flag?**

- **Unusual Ports**: Traffic using non-standard ports or protocols that normally carry no data
- **Beaconing**: Regular, short signals from an internal device to an external command-and-control server
- **Brute Force Signs**: Sudden spikes in failed login attempts followed by a successful login

---

### On file integrity:

**Which files are critical enough that any unexpected change should trigger an alert?**

**Critical Configuration and Security Files:**

- `/etc/passwd` and `/etc/shadow` – Store user account information and encrypted passwords; unauthorized changes signal new malicious accounts
- `/etc/sudoers` – Defines root and administrative privileges; monitoring prevents unauthorized users from gaining elevated powers
- `/etc/ssh/sshd_config` – Controls SSH access rules; changes can expose the server to remote attacks or unauthorized keys
- `/etc/crontab` and `/etc/cron.d/` – Manage automated tasks; attackers modify these for persistence
- `/etc/services` – Maps network services to ports; rogue entries signal hidden backdoors

**Critical System Binaries and Directories:**

- `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin` – Core system programs; changes indicate rootkits or compromised OS code
- `/tmp/` – Temporary storage often abused to drop exploit scripts and malicious payloads

**Critical Log Files:**

- `/var/log/auth.log` (Ubuntu/Debian) – Tracks login attempts, sudo usage, and authentication failures
- `/var/log/syslog` or `/var/log/messages` – Records general system and daemon operations
- `/var/log/audit/audit.log` – Detailed security auditing logs from the Linux auditing subsystem

**What file attributes or permissions are dangerous if misconfigured?**

- **Weak Permissions on /etc/passwd or /etc/shadow**: If writable, users can create root accounts; if readable, hashes can be cracked offline
- **World-Writable Binaries or Directories (777 permissions)**: Allows any user to replace legitimate binaries or drop malicious scripts
- **Misconfigured SUID/SGID Bits**: Allows regular users to execute binaries with root-level privileges, enabling instant privilege escalation
- **Overly Permissive sudoers File**: Blanket sudo access or permission to run interpreters (vim, find) lets users spawn root shells
- **Writable Scripts in System Paths or Cron**: If a root-run cron job points to a user-modifiable script, attackers can inject commands

**How do you detect whether a file was modified recently?**

- `find /etc -type f -mmin -60` – Files modified in the last 60 minutes
- `find /etc -type f -mtime -1` – Files modified in the last 24 hours
- `stat /etc/passwd` – Explicitly lists Access, Modify, and Change times down to the second

---

### On logging and alerting:

**Where do Linux systems store logs, and what does each file record?**

- `/var/log/auth.log` – Successful and failed SSH logins, sudo usage, user/group changes, PAM activity
- `/var/log/syslog` – Main general system log; global system messages, non-kernel service events, cron jobs, and daemon activities
- `/var/log/kern.log` – Exclusively kernel messages, hardware warnings, driver states, and low-level system alerts
- `/var/log/dpkg.log` – Package management activity
- `/var/log/faillog` – Failed login attempts per user account; query with `faillog` to monitor brute-force attacks
- `/var/log/apache2/` or `/var/log/nginx/` – Web server access and error logs if applicable

**Common commands for log inspection:**

- `tail -f /var/log/auth.log` – View live streaming logs
- `grep "Failed" /var/log/auth.log` – Search for failed logins
- `journalctl -u ssh` – Query systemd journal logs (alternative to plain text logs)

**What format do professional security tools use for structured alerts, and why does format matter?**

Alert components include:

- **Timestamp** – Exact date and time of the suspicious activity
- **Severity/Priority Level** – Rating (Low, Medium, High, Critical) indicating urgency
- **Source IP/Host** – Origin of the potential attacker or suspicious traffic
- **Destination IP/Host/Path/File** – The targeted system or asset
- **Event Type / Signature ID** – The specific rule, malware signature, or behavior triggering the alert
- **Impact Description** – Plain-language summary of what happened and its significance
- **Recommended Actions** – Steps for containment, patching, or mitigation

Common formats include JSON, CSV, XML, Syslog, and CEF. Format matters because it enables automated parsing, integration with other security tools, and consistent data exchange across systems.

**What differentiates a trustworthy alerting system from one that floods you with noise?**

- **Baseline Awareness**: A trustworthy system understands "normal" behavior. It doesn't alert every time a background process writes a temp file; it alerts only when activity deviates from an established baseline.
- **Rich Context**: Vague messages like "File changed" are useless, while specific alerts like "File /etc/passwd modified by UID 1001 (user: dev) using /usr/bin/vim (PID: 4120)" immediately clarify the issue.
- **Severity Tiers**: Events are categorized into clear priority levels (INFO, WARNING, CRITICAL), letting you respond to high-impact events first instead of treating everything as an emergency.
- **Aggregation and Deduplication**: Instead of sending an alert for each of 1,000 SSH login attempts in 30 seconds, a useful tool groups them together: "Brute-force attack detected: 1,000 failed SSH attempts from IP 192.168.1.50 within 30 seconds."
