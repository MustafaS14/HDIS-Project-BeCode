# HDIS-Project-BeCode
Bash-Based Host Intrusion Detection System (HIDS)
A Linux Capstone Project by a 3-Person Team

"The threat is already inside. Your job is to find it before it finds you."

🚀 Overview

Welcome to the GitHub repository for our Bash-Based Host Intrusion Detection System (HIDS)! Built entirely from scratch using native Linux tools and Bash scripting—without any third-party software dependencies—this project serves as a lightweight yet powerful security auditing and monitoring tool.

As part of our Linux Capstone Project, our team designed this system to tackle one of the most critical responsibilities of a SOC analyst or system administrator: monitoring, detecting, and reporting suspicious activity on a Linux machine.

📋 Table of Contents

Architecture & Modules

Project Phases

Requirements & Deliverables

Setup & Installation

Usage

Nice-to-Haves Implemented

⚙️ Architecture & Modules

The HIDS is structured around five core security pillars, ensuring comprehensive visibility into a running system:

System Health: Tracks crucial resource usage metrics (CPU, memory, load averages) and evaluates system stability against defined thresholds.

User Activity: Audits both historical and current user logins, checking for unauthorized accounts, unexpected remote sessions, or privilege escalations.

Process & Network Audit: Scans active processes, checks ownership, execution paths, and correlates them with open listening ports and active network connections.

File Integrity Monitoring (FIM): Establishes a cryptographic or metadata-based baseline of critical system files, detecting unauthorized modifications, permission errors, or dangerous SUID binaries.

Alerting System: Logs persistent security events with timestamps and severity levels, surfacing actionable intelligence while keeping noise to a minimum.

🗺️ Project Phases

Phase 1 — Research & Design (research.md)
Before writing a single line of Bash, our team investigated the problem space by analyzing enterprise HIDS solutions (such as Wazuh, OSSEC, Auditd, and Tripwire). We documented our findings on Linux internals (/proc, system logs, audit logs) in our research.md file, which guided our engineering choices regarding signal-to-noise ratios and baseline management.

Phase 2 — Implementation
We translated our research into clean, modular, and heavily commented Bash scripts addressing each of the five assessment areas.

🎯 Requirements & Deliverables

Baseline Coverage: Fully functional monitoring across all 5 core modules.

Persistent Logging: Writes actionable alerts to a dedicated log file with timestamps and severity indicators.

Automation: Configured to run seamlessly via scheduling or background execution.

Documentation: Includes an exhaustive research.md and an end-user-focused README.md.

Live Demonstration: Validated against simulated attack vectors (e.g., unauthorized user creation, modified system binaries, hidden listening ports).

🛠️ Setup & Installation

Clone the Repository:

Bash
git clone https://github.com/your-team/bash-hids.git
cd bash-hids
Make the Scripts Executable:

Bash
chmod +x hids.sh modules/*.sh
Configure Settings (Optional):
Modify the configuration file to adjust thresholds, whitelists, and log paths to fit your environment.

💻 Usage
Run the main auditing script with elevated privileges to access protected system logs and process information:

Bash
sudo ./hids.sh
To run individual modules separately (if using the modular architecture):

Bash
sudo ./modules/file_integrity.sh
✨ Nice-to-Haves & Advanced Features
Beyond the strict baseline requirements, our tool incorporates several advanced engineering features:

Baseline-Driven State Comparison: Automatically snapshots the machine on first run and flags delta deviations on subsequent checks.

Structured Alert Output: Formatted logs designed for easy parsing by external tools.

Whitelist Support: Reduces false positives by whitelisting known-good processes, system ports, and binaries.

Color-Coded Terminal Reports: Highlights critical and warning states for rapid triage.

Curious about our research findings, design decisions, or how we tackled alert fatigue? Dive into our documentation files or reach out to the team!
