#!/usr/bin/env bash
set -uo pipefail

declare -A RULE_IMPACT
declare -A RULE_ACTION

RULE_IMPACT[ALR-002]="The alert volume exceeded the configured run limit and non-critical alerts were suppressed."
RULE_ACTION[ALR-002]="Review the run output, reduce noisy detections, and raise the alert ceiling only if needed."

RULE_IMPACT[SYS-001]="CPU utilization is above the configured warning threshold."
RULE_ACTION[SYS-001]="Check the top CPU-consuming processes and confirm the load is expected."
RULE_IMPACT[SYS-002]="The 1-minute load average per core is above the configured warning threshold."
RULE_ACTION[SYS-002]="Inspect background jobs, CPU contention, and run queue pressure."
RULE_IMPACT[SYS-003]="The 1-minute load average per core is above the critical threshold."
RULE_ACTION[SYS-003]="Investigate runaway workloads or malicious activity immediately."
RULE_IMPACT[SYS-004]="Memory utilization is above the configured warning threshold."
RULE_ACTION[SYS-004]="Check for memory pressure, swapping, or processes consuming excessive RAM."
RULE_IMPACT[SYS-005]="Swap utilization is above the configured warning threshold."
RULE_ACTION[SYS-005]="Determine which processes are forcing swap usage and reduce memory pressure."
RULE_IMPACT[SYS-006]="At least one mounted filesystem is above the configured disk warning threshold."
RULE_ACTION[SYS-006]="Review disk usage and expand or clean the affected filesystem."
RULE_IMPACT[SYS-007]="At least one mounted filesystem is above the critical disk threshold."
RULE_ACTION[SYS-007]="Free space or isolate the host before services fail due to full disks."
RULE_IMPACT[SYS-008]="At least one monitored filesystem has exceeded the inode usage warning threshold."
RULE_ACTION[SYS-008]="Identify inode-heavy directories and remove unneeded files or trees."
RULE_IMPACT[SYS-100]="A system metrics snapshot was recorded for trend analysis."
RULE_ACTION[SYS-100]="Use the trend data for baselining and capacity planning."

RULE_IMPACT[USR-001]="A source produced repeated failed logins within the configured window."
RULE_ACTION[USR-001]="Review the source address, confirm whether the failures are expected, and look for follow-on success."
RULE_IMPACT[USR-002]="A source produced a high volume of failed logins within the configured window."
RULE_ACTION[USR-002]="Investigate for brute-force activity and block the source if appropriate."
RULE_IMPACT[USR-003]="A burst of failed logins from one source was followed by a successful login."
RULE_ACTION[USR-003]="Inspect the target account immediately and reset credentials if compromise is suspected."
RULE_IMPACT[USR-004]="A new account appeared compared with the stored baseline."
RULE_ACTION[USR-004]="Confirm the account owner, purpose, and creation time before leaving it enabled."
RULE_IMPACT[USR-005]="An account with root-equivalent privileges was created or modified."
RULE_ACTION[USR-005]="Lock the account (passwd -l), inspect /var/log/auth.log for its creation, and review sudo history."
RULE_IMPACT[USR-006]="A shadow entry contains an empty password field."
RULE_ACTION[USR-006]="Disable the account immediately and replace the password hash with a secure value."
RULE_IMPACT[USR-007]="A privileged group gained a new member."
RULE_ACTION[USR-007]="Verify the user was intentionally granted elevated access and remove it if not."
RULE_IMPACT[USR-008]="An account shell changed from a non-login shell to an interactive shell."
RULE_ACTION[USR-008]="Check whether the change was authorized and review who performed it."
RULE_IMPACT[USR-009]="An authorized_keys file was added or modified under a user home directory."
RULE_ACTION[USR-009]="Review the key source, compare fingerprints, and remove unauthorized access keys."
RULE_IMPACT[USR-012]="A shell history file is empty or redirected to /dev/null."
RULE_ACTION[USR-012]="Inspect the account for tampering and restore normal shell history recording."
RULE_IMPACT[USR-014]="/etc/shadow permissions or ownership do not match the expected secure values."
RULE_ACTION[USR-014]="Restore root ownership and restrict the file mode to 0640 or 0600."
RULE_IMPACT[USR-015]="/etc/passwd is writable by a non-root user."
RULE_ACTION[USR-015]="Remove write access immediately and inspect the host for privilege escalation."
RULE_IMPACT[USR-016]="An account with no prior lastlog entry logged in for the first time."
RULE_ACTION[USR-016]="Confirm the login was expected and check surrounding authentication events."

RULE_IMPACT[PRC-001]="A process is executing from a writable directory."
RULE_ACTION[PRC-001]="Identify the binary, quarantine it if needed, and move it to a trusted path."
RULE_IMPACT[PRC-002]="A process executable has been deleted from disk while still running."
RULE_ACTION[PRC-002]="Capture the binary from memory or quarantine the host for investigation."
RULE_IMPACT[PRC-003]="A root-owned process has a suspicious parent shell or web server."
RULE_ACTION[PRC-003]="Trace the process tree and verify whether the parent-child relationship is legitimate."
RULE_IMPACT[PRC-004]="A bracketed kernel-style process name has a real on-disk executable."
RULE_ACTION[PRC-004]="Inspect the executable path and compare it with the reported process name."
RULE_IMPACT[PRC-005]="A PID exists under /proc but not in ps output."
RULE_ACTION[PRC-005]="Verify whether the process is hidden and capture evidence immediately."
RULE_IMPACT[PRC-006]="A service account is running an interactive shell."
RULE_ACTION[PRC-006]="Terminate the shell, disable the account if appropriate, and review the access path."
RULE_IMPACT[PRC-009]="A suspicious binary from the configured list is running."
RULE_ACTION[PRC-009]="Inspect the command line and provenance of the executable before allowing it to continue."

RULE_IMPACT[NET-001]="A listener is bound to a port that is not on the whitelist."
RULE_ACTION[NET-001]="Identify the process behind the listener and confirm the service is authorized."
RULE_IMPACT[NET-002]="A listener is bound to 0.0.0.0 on a non-whitelisted port."
RULE_ACTION[NET-002]="Restrict the bind address or stop the unexpected service."
RULE_IMPACT[NET-005]="An interface is in promiscuous mode."
RULE_ACTION[NET-005]="Check packet capture or sniffing tools and disable promiscuous mode if not required."

RULE_IMPACT[FIM-001]="A Tier 1 monitored file hash changed."
RULE_ACTION[FIM-001]="Restore the file from a trusted source and investigate the modification path."
RULE_IMPACT[FIM-002]="A Tier 1 monitored file is missing."
RULE_ACTION[FIM-002]="Recover the file immediately and review deletion or tampering activity."
RULE_IMPACT[FIM-003]="A Tier 2 monitored file changed or was added."
RULE_ACTION[FIM-003]="Verify whether the change was expected and preserve a copy for analysis."
RULE_IMPACT[FIM-004]="The mode of a monitored file changed."
RULE_ACTION[FIM-004]="Restore the expected permissions and inspect the actor that changed them."
RULE_IMPACT[FIM-005]="The owner or group of a monitored file changed."
RULE_ACTION[FIM-005]="Restore the expected ownership and investigate privilege changes."
RULE_IMPACT[FIM-006]="A new SUID or SGID binary appeared compared with the baseline."
RULE_ACTION[FIM-006]="Inspect the binary, remove the SUID or SGID bit if unauthorized, and determine how it appeared."
RULE_IMPACT[FIM-007]="A SUID binary exists outside the trusted system directories."
RULE_ACTION[FIM-007]="Treat the binary as suspicious, isolate it, and verify whether it was intentionally installed."
RULE_IMPACT[FIM-008]="/etc/ld.so.preload exists on the host."
RULE_ACTION[FIM-008]="Remove the preload entry after validating the system libraries and persistence risk."
RULE_IMPACT[FIM-010]="A cron-related monitored path changed."
RULE_ACTION[FIM-010]="Review the scheduled task and remove unauthorized persistence."
RULE_IMPACT[FIM-012]="A monitored log file is smaller than it was at baseline."
RULE_ACTION[FIM-012]="Check for log truncation or tampering and preserve the evidence before rotation."
RULE_IMPACT[FIM-014]="No trusted baseline existed when the check ran."
RULE_ACTION[FIM-014]="Establish a baseline only after the host has been verified clean."

# Returns the impact description for a rule ID, or a generic fallback.
rule_impact() {
  local rule_id="${1:-}"
  if [ -n "${RULE_IMPACT[${rule_id}]:-}" ]; then
    printf '%s' "${RULE_IMPACT[$rule_id]}"
    return 0
  fi
  printf '%s' "No impact guidance is defined for ${rule_id}."
}

# Returns the recommended action for a rule ID, or a generic fallback.
rule_action() {
  local rule_id="${1:-}"
  if [ -n "${RULE_ACTION[${rule_id}]:-}" ]; then
    printf '%s' "${RULE_ACTION[$rule_id]}"
    return 0
  fi
  printf '%s' "No recommended action is defined for ${rule_id}."
}