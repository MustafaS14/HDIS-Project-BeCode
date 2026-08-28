#!/usr/bin/env bash
set -u
set -o pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${PROJECT_ROOT}/.hids"
LOG_FILE="${STATE_DIR}/hids.log"
BASELINE_DIR="${STATE_DIR}/baseline"
DEMO_FILE="${STATE_DIR}/demo_target.txt"
SUSPICIOUS_PORT="8888"
CRITICAL_FILES=(
  "${DEMO_FILE}"
  "/etc/passwd"
  "/etc/hosts"
  "/etc/ssh/sshd_config"
  "/etc/sudoers"
)
HEALTH_CPU_THRESHOLD=80
HEALTH_MEMORY_THRESHOLD=85
HEALTH_DISK_THRESHOLD=85
SUSPICIOUS_PROCESS_NAMES=(
  "nc"
  "ncat"
  "netcat"
  "bash"
  "python"
  "python3"
  "perl"
  "ruby"
  "openssl"
)

# Creates the project state directories used by the HIDS to store logs and baselines.
ensure_state_dir() {
  mkdir -p "${STATE_DIR}" "${BASELINE_DIR}"
  touch "${LOG_FILE}"
}

# Records a timestamped alert in the persistent log file with severity and module metadata.
log_event() {
  local severity="${1:-LOW}"
  local module="${2:-general}"
  local message="${3:-No message provided}"
  local stamp
  stamp="$(date '+%Y-%m-%d %H:%M:%S %Z')"
  local json_message
  json_message="${message//\\/\\\\}"
  json_message="${json_message//\"/\\\"}"
  json_message="${json_message//$'\n'/\\n}"
  json_message="${json_message//$'\r'/}"
  json_message="${json_message//$'\t'/\\t}"
  printf '{"timestamp":"%s","severity":"%s","module":"%s","message":"%s"}\n' "${stamp}" "${severity}" "${module}" "${json_message}" >> "${LOG_FILE}"
}

# Module 1: checks if the system is currently healthy by reviewing CPU, memory, and disk usage.
module_system_health() {
  local cpu_usage=0
  local mem_used=0
  local mem_total=0
  local disk_usage=0
  local load_avg=""

  if [ -r /proc/stat ]; then
    local cpu_line
    cpu_line="$(grep '^cpu ' /proc/stat 2>/dev/null)"
    if [ -n "${cpu_line}" ]; then
      read -r _ a b c d e f g h i j <<< "${cpu_line}"
      local idle_now=$((d + e))
      local total_now=$((a + b + c + d + e + f + g + h + i + j))
      local prev_total="${PREV_TOTAL:-0}"
      local prev_idle="${PREV_IDLE:-0}"

      if [ "${prev_total}" -gt 0 ]; then
        local total_delta=$((total_now - prev_total))
        local idle_delta=$((idle_now - prev_idle))
        if [ "${total_delta}" -gt 0 ]; then
          cpu_usage=$((100 * (total_delta - idle_delta) / total_delta))
        fi
      fi
      PREV_TOTAL="${total_now}"
      PREV_IDLE="${idle_now}"
    fi
  fi

  if [ -r /proc/meminfo ]; then
    mem_total="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null)"
    mem_used="$(awk '/MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null)"
    if [ -n "${mem_total}" ] && [ "${mem_total}" -gt 0 ] && [ -n "${mem_used}" ] && [ -n "${mem_total}" ]; then
      local mem_available
      mem_available="${mem_used}"
      local mem_used_percent=$((100 - 100 * mem_available / mem_total))
      mem_used="${mem_used_percent}"
    fi
  fi

  if command -v df >/dev/null 2>&1; then
    disk_usage="$(df -P / 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%')"
  fi

  if command -v uptime >/dev/null 2>&1; then
    load_avg="$(uptime | sed -E 's/.*load average: //')"
  fi

  if [ "${cpu_usage}" -ge "${HEALTH_CPU_THRESHOLD}" ] || [ "${mem_used}" -ge "${HEALTH_MEMORY_THRESHOLD}" ] || [ "${disk_usage:-0}" -ge "${HEALTH_DISK_THRESHOLD}" ]; then
    log_event "WARNING" "system_health" "CPU=${cpu_usage}% MEM=${mem_used}% DISK=${disk_usage:-0}% LOAD=${load_avg:-unknown}; resource usage above healthy threshold"
  else
    log_event "LOW" "system_health" "CPU=${cpu_usage}% MEM=${mem_used}% DISK=${disk_usage:-0}% LOAD=${load_avg:-unknown}; system appears healthy"
  fi
}

# Module 2: checks for current and recent user activity to spot abnormal logins or unexpected accounts.
module_user_activity() {
  local current_users
  current_users="$(who 2>/dev/null || true)"
  local recent_logins
  recent_logins="$(last -n 10 2>/dev/null || true)"
  local failed_logins
  failed_logins="$(lastb -n 10 2>/dev/null || true)"

  if [ -n "${current_users}" ]; then
    log_event "LOW" "user_activity" "Current active sessions: ${current_users}"
  else
    log_event "LOW" "user_activity" "No users are currently logged in"
  fi

  if [ -n "${failed_logins}" ]; then
    log_event "MEDIUM" "user_activity" "Recent failed login attempts: ${failed_logins}"
  fi

  if [ -n "${recent_logins}" ]; then
    log_event "LOW" "user_activity" "Recent login activity: ${recent_logins}"
  else
    log_event "LOW" "user_activity" "No recent login history available"
  fi
}

# Module 3: audits running processes and listening ports for suspicious or unauthorized activity.
module_process_network() {
  local suspicious_processes=""
  local process_entry
  while IFS= read -r process_entry; do
    [ -z "${process_entry}" ] && continue
    local proc_name
    proc_name="$(printf '%s' "${process_entry}" | awk '{print $1}')"
    for suspect in "${SUSPICIOUS_PROCESS_NAMES[@]}"; do
      if [ "${proc_name}" = "${suspect}" ]; then
        suspicious_processes+="${process_entry}\n"
        break
      fi
    done
  done < <(ps -eo comm --no-headers 2>/dev/null | sort -u)

  if [ -n "${suspicious_processes}" ]; then
    log_event "MEDIUM" "process_network" "Suspicious running processes detected: ${suspicious_processes}"
  else
    log_event "LOW" "process_network" "No obviously suspicious processes detected"
  fi

  local network_summary
  if command -v ss >/dev/null 2>&1; then
    network_summary="$(ss -tulnp 2>/dev/null | tail -n +2)"
  elif command -v netstat >/dev/null 2>&1; then
    network_summary="$(netstat -tuln 2>/dev/null)"
  else
    network_summary=""
  fi

  if [ -n "${network_summary}" ]; then
    log_event "LOW" "process_network" "Current listeners: ${network_summary}"
  else
    log_event "LOW" "process_network" "No network listeners identified by ss/netstat"
  fi
}

# Creates a baseline snapshot for monitored files, processes, users, network listeners, and SUID/SGID files.
write_baselines() {
  ensure_state_dir

  : > "${BASELINE_DIR}/file_hashes.txt"
  for file_path in "${CRITICAL_FILES[@]}"; do
    if [ -e "${file_path}" ]; then
      local digest
      digest="$(sha256sum "${file_path}" 2>/dev/null | awk '{print $1}')"
      printf '%s\t%s\n' "${file_path}" "${digest}" >> "${BASELINE_DIR}/file_hashes.txt"
    fi
  done

  ps -eo comm --no-headers 2>/dev/null | sort -u > "${BASELINE_DIR}/processes.txt"

  if command -v ss >/dev/null 2>&1; then
    ss -tulnp 2>/dev/null | sort > "${BASELINE_DIR}/network.txt"
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tuln 2>/dev/null | sort > "${BASELINE_DIR}/network.txt"
  else
    : > "${BASELINE_DIR}/network.txt"
  fi

  getent passwd 2>/dev/null | sort > "${BASELINE_DIR}/users.txt"

  if command -v find >/dev/null 2>&1; then
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort > "${BASELINE_DIR}/privileged.txt"
  else
    : > "${BASELINE_DIR}/privileged.txt"
  fi

  log_event "LOW" "baseline" "Baseline snapshot created at ${BASELINE_DIR}"
}

# Module 4: compares monitored files against a known-good snapshot and flags file changes or deletions.
check_file_integrity() {
  if [ ! -f "${BASELINE_DIR}/file_hashes.txt" ]; then
    write_baselines
    return 0
  fi

  local changed=0
  while IFS=$'\t' read -r target digest; do
    [ -z "${target:-}" ] && continue
    if [ ! -e "${target}" ]; then
      log_event "HIGH" "file_integrity" "Critical file missing: ${target}"
      changed=1
      continue
    fi

    local current_digest
    current_digest="$(sha256sum "${target}" 2>/dev/null | awk '{print $1}')"
    if [ "${current_digest}" != "${digest}" ]; then
      log_event "HIGH" "file_integrity" "Integrity change detected for ${target}"
      changed=1
    fi
  done < "${BASELINE_DIR}/file_hashes.txt"

  if [ "${changed}" -eq 0 ]; then
    log_event "LOW" "file_integrity" "No file integrity issues detected"
  fi
}

# Checks whether new command names appeared in the process table and flags unexpected executables.
check_process_activity() {
  if [ ! -f "${BASELINE_DIR}/processes.txt" ]; then
    write_baselines
    return 0
  fi

  local current_processes
  current_processes="$(ps -eo comm --no-headers 2>/dev/null | sort -u)"
  local delta
  delta="$(comm -13 <(sort "${BASELINE_DIR}/processes.txt") <(printf '%s\n' "${current_processes}" | sort))"

  if [ -n "${delta}" ]; then
    log_event "MEDIUM" "process_monitor" "Unexpected new processes detected: ${delta}"
  else
    log_event "LOW" "process_monitor" "No unexpected process activity detected"
  fi
}

# Looks for unexpected listening ports by comparing the current network listener state to its stored baseline.
check_network_activity() {
  if [ ! -f "${BASELINE_DIR}/network.txt" ]; then
    write_baselines
    return 0
  fi

  local current_network
  if command -v ss >/dev/null 2>&1; then
    current_network="$(ss -tulnp 2>/dev/null | sort)"
  elif command -v netstat >/dev/null 2>&1; then
    current_network="$(netstat -tuln 2>/dev/null | sort)"
  else
    current_network=""
  fi

  local delta
  delta="$(comm -13 <(sort "${BASELINE_DIR}/network.txt") <(printf '%s\n' "${current_network}" | sort))"

  if [ -n "${delta}" ]; then
    log_event "HIGH" "network_monitor" "Unexpected network listener detected: ${delta}"
  else
    log_event "LOW" "network_monitor" "No unexpected network listeners detected"
  fi
}

# Reviews local user and authentication data to spot accounts or groups that were created unexpectedly.
check_user_activity() {
  if [ ! -f "${BASELINE_DIR}/users.txt" ]; then
    write_baselines
    return 0
  fi

  local current_users
  current_users="$(getent passwd 2>/dev/null | sort)"
  local delta
  delta="$(comm -13 <(sort "${BASELINE_DIR}/users.txt") <(printf '%s\n' "${current_users}" | sort))"

  if [ -n "${delta}" ]; then
    log_event "MEDIUM" "user_monitor" "New user or account change detected: ${delta}"
  else
    log_event "LOW" "user_monitor" "No new user accounts detected"
  fi
}

# Scans the filesystem for new SUID/SGID binaries or privileged executables that could indicate escalation attempts.
check_privilege_activity() {
  if [ ! -f "${BASELINE_DIR}/privileged.txt" ]; then
    write_baselines
    return 0
  fi

  local current_privileged
  if command -v find >/dev/null 2>&1; then
    current_privileged="$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort)"
  else
    current_privileged=""
  fi

  local delta
  delta="$(comm -13 <(sort "${BASELINE_DIR}/privileged.txt") <(printf '%s\n' "${current_privileged}" | sort))"

  if [ -n "${delta}" ]; then
    log_event "HIGH" "privilege_monitor" "New privileged binary detected: ${delta}"
  else
    log_event "LOW" "privilege_monitor" "No new privileged binaries detected"
  fi
}

# Detects traffic or listening sockets using non-standard or high-risk ports that normally carry no data.
check_unusual_ports() {
  ensure_state_dir

  local suspicious_ports="4444|6667|31337|4443|8888|1337|6666|6668|6669|12345|9999"
  local unusual_traffic=""

  if command -v ss >/dev/null 2>&1; then
    unusual_traffic="$(ss -tulnp 2>/dev/null | grep -E ":(${suspicious_ports})[[:space:]]" || true)"
    if [ -z "${unusual_traffic}" ]; then
      unusual_traffic="$(ss -tun 2>/dev/null | grep -E ":(${suspicious_ports})[[:space:]]" || true)"
    fi
  elif command -v netstat >/dev/null 2>&1; then
    unusual_traffic="$(netstat -tuln 2>/dev/null | grep -E ":(${suspicious_ports})[[:space:]]" || true)"
  fi

  if [ -n "${unusual_traffic}" ]; then
    log_event "HIGH" "unusual_ports" "Unusual port activity detected on non-standard port: ${unusual_traffic}"
  fi
}

# Detects regular periodic signals sent from an internal device to an external command-and-control server (Beaconing).
check_beaconing() {
  ensure_state_dir
  local beacon_store="${STATE_DIR}/beacon_history.txt"

  local current_conns=""
  if command -v ss >/dev/null 2>&1; then
    current_conns="$(ss -tun 2>/dev/null | grep 'ESTAB' | awk '{print $5}' | grep -v '^127\.' | grep -v '^::1' | grep -v '^0\.0\.0\.0' | sort -u || true)"
  elif command -v netstat >/dev/null 2>&1; then
    current_conns="$(netstat -tun 2>/dev/null | grep 'ESTABLISHED' | awk '{print $5}' | grep -v '^127\.' | grep -v '^::1' | grep -v '^0\.0\.0\.0' | sort -u || true)"
  fi

  if [ -n "${current_conns}" ]; then
    echo "${current_conns}" >> "${beacon_store}"
    local trimmed
    trimmed="$(tail -n 50 "${beacon_store}" 2>/dev/null || true)"
    echo "${trimmed}" > "${beacon_store}"

    local repeated_endpoints
    repeated_endpoints="$(sort "${beacon_store}" | uniq -c | awk '$1 >= 3 {print $2}' | tr '\n' ' ')"
    if [ -n "${repeated_endpoints}" ]; then
      log_event "HIGH" "beaconing" "Command & Control beaconing pattern detected: repeated periodic signals to ${repeated_endpoints}"
    fi
  fi
}

# Detects brute force signs: sudden spikes in failed login attempts followed by a successful login.
check_brute_force() {
  ensure_state_dir

  local failed_count=0
  if command -v lastb >/dev/null 2>&1; then
    failed_count="$(lastb -n 20 2>/dev/null | grep -v '^$' | grep -v '^wtmp' | grep -v '^btmp' | wc -l | tr -d ' ')"
  fi

  local active_login=""
  if command -v who >/dev/null 2>&1; then
    active_login="$(who 2>/dev/null | head -n 1 || true)"
  fi
  local recent_login=""
  if command -v last >/dev/null 2>&1; then
    recent_login="$(last -n 5 2>/dev/null | grep -v '^$' | grep -v '^wtmp' | grep -v 'reboot' | head -n 1 || true)"
  fi

  if [ "${failed_count}" -ge 3 ] && { [ -n "${active_login}" ] || [ -n "${recent_login}" ]; }; then
    local user_name
    user_name="$(echo "${active_login:-${recent_login}}" | awk '{print $1}')"
    log_event "HIGH" "brute_force" "Brute force attack pattern detected: spike of ${failed_count} failed login attempts followed by successful login for user '${user_name:-unknown}'"
  fi
}

# Module 5: centralizes alert severity and persistence so real issues are surfaced in a readable log.
generate_summary() {
  ensure_state_dir
  local summary_file="${STATE_DIR}/summary.txt"
  local recent_lines
  recent_lines="$(tail -n 20 "${LOG_FILE}" 2>/dev/null || true)"

  {
    echo "HIDS Summary"
    echo "Generated at: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "Log file: ${LOG_FILE}"
    echo ""
    echo "Recent alerts:"
    if [ -n "${recent_lines}" ]; then
      printf '%s\n' "${recent_lines}"
    else
      echo "No events recorded yet."
    fi
  } > "${summary_file}"

  log_event "LOW" "summary" "Summary report generated at ${summary_file}"
}

# Installs a cron entry so the HIDS runs automatically at a fixed interval without manual intervention.
install_scheduler() {
  ensure_state_dir

  local cron_line="0 * * * * ${USER:-root} bash ${PROJECT_ROOT}/HIDS.sh --once >/dev/null 2>&1"

  if [ "$(id -u)" -eq 0 ]; then
    local cron_file="/etc/cron.d/hids-monitor"
    printf '%s\n' "SHELL=/bin/bash" > "${cron_file}"
    printf '%s\n' "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" >> "${cron_file}"
    printf '%s\n' "${cron_line//${USER:-root}/root}" >> "${cron_file}"
    chmod 0644 "${cron_file}"
    log_event "LOW" "scheduler" "Cron job installed at ${cron_file}"
    echo "Scheduler installed at ${cron_file}"
  else
    if command -v crontab >/dev/null 2>&1; then
      local user_cron
      user_cron="$(mktemp)"
      crontab -l 2>/dev/null > "${user_cron}"
      if ! grep -Fq "HIDS.sh --once" "${user_cron}" 2>/dev/null; then
        printf '%s\n' "${cron_line}" >> "${user_cron}"
        crontab "${user_cron}"
      fi
      rm -f "${user_cron}"
      log_event "LOW" "scheduler" "User cron entry installed for ${USER}"
      echo "Scheduler installed via user crontab"
    else
      log_event "WARNING" "scheduler" "cron is not available; automatic scheduling could not be configured"
      echo "cron is not available on this system. Install cron or use systemd timers manually."
    fi
  fi
}

# Prints the usage instructions and supported command-line arguments for the HIDS tool.
print_help() {
  cat <<'USAGE'
HIDS Bash Project

Usage:
  ./HIDS.sh --baseline
  ./HIDS.sh --once
  ./HIDS.sh --ship-elk
  ./HIDS.sh --email-report
  ./HIDS.sh --demo
  ./HIDS.sh --install-cron
  ./HIDS.sh --help

Options:
  --baseline      Create the initial reference snapshot without scanning.
  --once          Run one complete inspection cycle and log any findings.
  --ship-elk      Run one inspection cycle, then ship new events to Elasticsearch.
  --email-report  Run inspection cycle and send an email report if EMAIL_TO is set.
  --demo          Simulate an attack sequence that triggers log alerts.
  --install-cron  Add a recurring cron job for automatic monitoring hourly.
  --help          Show this help menu.
USAGE
}

# Sends an email security report if send_email_report.sh is available.
send_email_after_scan() {
  local email_script="${PROJECT_ROOT}/send_email_report.sh"

  if [ -f "${email_script}" ]; then
    bash "${email_script}" 30
  fi
}

# Runs one local scan and then ships new events to Elasticsearch using elk_ship.sh.
ship_after_scan() {
  local ship_script="${PROJECT_ROOT}/elk_ship.sh"

  run_checks

  if [ ! -f "${ship_script}" ]; then
    log_event "WARNING" "elk_ship" "ELK shipper script not found at ${ship_script}"
    echo "ELK shipper script not found at ${ship_script}"
    return 1
  fi

  if ! bash "${ship_script}" --once; then
    log_event "WARNING" "elk_ship" "ELK shipping failed; check ELASTIC_URL/ELASTIC_API_KEY and network access"
    echo "ELK shipping failed. Verify ELASTIC_URL, ELASTIC_API_KEY, and connectivity."
    return 1
  fi

  log_event "LOW" "elk_ship" "ELK shipping completed successfully"
  echo "HIDS scan complete and new events shipped to Elasticsearch."

  if [ -n "${EMAIL_TO:-}" ]; then
    send_email_after_scan
  fi
}

# Simulates a malicious workflow using only native shell actions.
run_demo() {
  ensure_state_dir
  touch "${DEMO_FILE}"
  printf 'malicious-change\n' >> "${DEMO_FILE}"

  log_event "HIGH" "demo" "Simulated malicious file modification written to ${DEMO_FILE}"
  echo "Demo scenario started. Running HIDS checks now..."
  run_checks
}

# Runs the full check set in sequence: file integrity, process, network, user, privilege, unusual ports, beaconing, and brute force monitoring.
run_checks() {
  ensure_state_dir

  module_system_health
  module_user_activity
  check_brute_force
  module_process_network
  check_file_integrity
  check_process_activity
  check_network_activity
  check_unusual_ports
  check_beaconing
  check_user_activity
  check_privilege_activity
  generate_summary
}

# Handles the command-line interface and dispatches the right action.
main() {
  case "${1:---help}" in
    --baseline)
      write_baselines
      echo "Baseline created successfully at ${BASELINE_DIR}"
      ;;
    --once)
      run_checks
      echo "HIDS scan complete. Results saved in ${LOG_FILE}"
      if [ -n "${EMAIL_TO:-}" ]; then
        send_email_after_scan
      fi
      ;;
    --ship-elk)
      ship_after_scan
      ;;
    --email-report)
      run_checks
      send_email_after_scan
      ;;
    --demo)
      if [ ! -f "${BASELINE_DIR}/file_hashes.txt" ]; then
        write_baselines
      fi
      run_demo
      echo "Demo alert generated in ${LOG_FILE}"
      ;;
    --install-cron)
      install_scheduler
      ;;
    --help|-h)
      print_help
      ;;
    *)
      print_help
      ;;
  esac
}

main "$@"
