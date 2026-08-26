# <strong><span style="font-size: 3em;">💻🛡️ HIDS-Project-BeCode</span></strong>

## <strong><span style="font-size: 2em;">Bash-Based Host Intrusion Detection System (HIDS)</span></strong>
### <strong><span style="font-size: 1.4em;">A Linux Capstone Project by a 3-Person Team</span></strong>

> <strong><span style="font-size: 1.2em;">"The threat is already inside. Your job is to find it before it finds you."</span></strong>

---

## <strong><span style="font-size: 1.8em;">🚀🚀🚀 Overview</span></strong>

Welcome to the GitHub repository for our **Bash-Based Host Intrusion Detection System (HIDS)**!  
Built entirely from scratch using native Linux tools and Bash scripting—without any third-party software dependencies.

As part of our Linux Capstone Project, our team designed this system to tackle one of the most critical responsibilities of a SOC analyst or system administrator: **monitoring, detecting, and reporting suspicious host activity**.

---

## <strong><span style="font-size: 1.8em;">📋📋📋 Table of Contents</span></strong>

- [Architecture & Modules](#architecture--modules)
- [Project Phases](#project-phases)
- [Requirements & Deliverables](#requirements--deliverables)
- [Setup & Installation](#setup--installation)
- [Usage](#usage)
- [Nice-to-Haves & Advanced Features](#nice-to-haves--advanced-features)

---

## <a id="architecture--modules"></a><strong><span style="font-size: 1.8em;">⚙️⚙️⚙️ Architecture & Modules</span></strong>

The HIDS is structured around five core security pillars, ensuring comprehensive visibility into a running system:

### <strong><span style="font-size: 1.3em;">1) System Health</span></strong>
Tracks crucial resource usage metrics (CPU, memory, load averages) and evaluates system stability against defined thresholds.

### <strong><span style="font-size: 1.3em;">2) User Activity</span></strong>
Audits both historical and current user logins, checking for unauthorized accounts, unexpected remote sessions, or privilege escalations.

### <strong><span style="font-size: 1.3em;">3) Process & Network Audit</span></strong>
Scans active processes, checks ownership, execution paths, and correlates them with open listening ports and active network connections.

### <strong><span style="font-size: 1.3em;">4) File Integrity Monitoring (FIM)</span></strong>
Establishes a cryptographic or metadata-based baseline of critical system files, detecting unauthorized modifications, permission errors, or dangerous SUID binaries.

### <strong><span style="font-size: 1.3em;">5) Alerting System</span></strong>
Logs persistent security events with timestamps and severity levels, surfacing actionable intelligence while keeping noise to a minimum.

---

## <a id="project-phases"></a><strong><span style="font-size: 1.8em;">🗺️🗺️🗺️ Project Phases</span></strong>

### <strong><span style="font-size: 1.3em;">Phase 1 — Research & Design (`research.md`)</span></strong>
Before writing a single line of Bash, our team investigated the problem space by analyzing enterprise HIDS solutions (such as Wazuh, OSSEC, Auditd, and Tripwire).  
We documented our findings on Linux intrusion detection strategies, threat models, and tool architecture decisions.

### <strong><span style="font-size: 1.3em;">Phase 2 — Implementation</span></strong>
We translated our research into clean, modular, and heavily commented Bash scripts addressing each of the five assessment areas.

---

## <a id="requirements--deliverables"></a><strong><span style="font-size: 1.8em;">🎯🎯🎯 Requirements & Deliverables</span></strong>

- **Baseline Coverage:** Fully functional monitoring across all 5 core modules.
- **Persistent Logging:** Writes actionable alerts to a dedicated log file with timestamps and severity indicators.
- **Automation:** Configured to run seamlessly via scheduling or background execution.
- **Documentation:** Includes an exhaustive `research.md` and an end-user-focused `README.md`.
- **Live Demonstration:** Validated against simulated attack vectors (e.g., unauthorized user creation, modified system binaries, hidden listening ports).

---

## <a id="setup--installation"></a><strong><span style="font-size: 1.8em;">🛠️🛠️🛠️ Setup & Installation</span></strong>

### <strong><span style="font-size: 1.3em;">Clone the Repository</span></strong>

```bash
git clone https://github.com/your-team/bash-hids.git
cd bash-hids
```

### <strong><span style="font-size: 1.3em;">Make the Scripts Executable</span></strong>

```bash
chmod +x hids.sh modules/*.sh
```

### <strong><span style="font-size: 1.3em;">Configure Settings (Optional)</span></strong>
Modify the configuration file to adjust thresholds, whitelists, and log paths to fit your environment.

---

## <a id="usage"></a><strong><span style="font-size: 1.8em;">💻💻💻 Usage</span></strong>

Run the main auditing script with elevated privileges to access protected system logs and process information:

```bash
sudo ./hids.sh
```

To run individual modules separately (if using the modular architecture):

```bash
sudo ./modules/file_integrity.sh
```

---

## <a id="nice-to-haves--advanced-features"></a><strong><span style="font-size: 1.8em;">✨✨✨ Nice-to-Haves & Advanced Features</span></strong>

Beyond the strict baseline requirements, our tool incorporates several advanced engineering features:

- **Baseline-Driven State Comparison:** Automatically snapshots the machine on first run and flags delta deviations on subsequent checks.
- **Structured Alert Output:** Formatted logs designed for easy parsing by external tools.
- **Whitelist Support:** Reduces false positives by whitelisting known-good processes, system ports, and binaries.
- **Color-Coded Terminal Reports:** Highlights critical and warning states for rapid triage.

Curious about our research findings, design decisions, or how we tackled alert fatigue?  
Dive into our documentation files or reach out to the team!
