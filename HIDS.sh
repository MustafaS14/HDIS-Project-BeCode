#!/usr/bin/env bash
# HIDS primary scheduled runner.
set -u
set -o pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${PROJECT_ROOT}/.hids"
LOG_FILE="${STATE_DIR}/hids.log"
BASELINE_DIR="${STATE_DIR}/baseline"

load_local_environment() {
  local config_file="${PROJECT_ROOT}/email_config.env"

  if [ -f "${config_file}" ]; then
    set -a
    # shellcheck disable=SC1090
    . "${config_file}"
    set +a
  fi
}

DEMO_FILE="${STATE_DIR}/demo_target.txt"
SUSPICIOUS_PORT="8888"
ZERO_HASH="0000000000000000000000000000000000000000000000000000000000000000"
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
# Per-metric thresholds used by module_system_health's multi-metric severity scoring.
HEALTH_IOWAIT_THRESHOLD=25
HEALTH_LOAD_PER_CORE_THRESHOLD=1.0
HEALTH_INODE_THRESHOLD=80
HEALTH_SSD_AWAIT_MS=2
HEALTH_HDD_AWAIT_MS=20
HEALTH_TCP_RETRANS_PCT=1.5
HEALTH_FD_USAGE_PCT=75
HEALTH_CPU_TEMP_C=80
HEALTH_STATE_FILE="${STATE_DIR}/system_health.state"
# Number of exceeded metrics required to escalate system_health severity from MEDIUM to HIGH.
HEALTH_HIGH_SEVERITY_COUNT=3
FAILED_LOGIN_WARN=5
FAILED_LOGIN_CRIT=20
FAILED_LOGIN_WINDOW_MIN=10
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
# Insider-threat / post-compromise behavior detection (Module 2.5): recon commands, sudo/su
# abuse, persistence-file tampering, history clearing, and process masquerading.
USER_BEHAVIOR_STATE_DIR="${STATE_DIR}/user_behavior"
RECON_COMMAND_REGEX='(^|[[:space:]/])(whoami|uname -a|uname[[:space:]]+-a)([[:space:]]|$)|(^|[[:space:]])id([[:space:]]|$)'
SUID_SCAN_REGEX='find[[:space:]].*-perm[[:space:]]+.*(4000|u=s)'
HISTORY_TAMPER_REGEX='(^|[[:space:];|])(history[[:space:]]+-[[:alnum:]]*[cwd][[:alnum:]]*|history[[:space:]]+--(clear|write|delete)|unset[[:space:]]+HIST[A-Z_]*|((export|declare|typeset)[[:space:]]+)?HIST(SIZE|FILESIZE)=0|HISTFILE=/dev/null|set[[:space:]]+\+o[[:space:]]+history|shopt[[:space:]]+-u[[:space:]]+(cmdhist|lithist)|(rm|shred|unlink|truncate)[[:space:]].*(~\/|/[^[:space:]]*/)?\.(bash|zsh|sh)_history|([:>][[:space:]]*|echo[[:space:]].*>[[:space:]]*).*(~\/|/[^[:space:]]*/)?\.(bash|zsh|sh)_history)([[:space:];|]|$)'
AUTH_LOG_CANDIDATES=("/var/log/auth.log" "/var/log/secure")
SUDO_SU_FREQUENCY_THRESHOLD=3
SYSTEM_PROCESS_NAMES=(
  "systemd"
  "sshd"
  "cron"
  "crond"
  "init"
  "dbus-daemon"
  "rsyslogd"
  "kworker"
  "udevd"
)
SYSTEM_PROCESS_DIR_REGEX='^/(usr/)?s?bin/|^/usr/lib/systemd/|^/lib/systemd/|^/usr/lib/udev/'
# auditd (kernel-level execve logging) catches recon commands in real time regardless of shell
# history settings, shell type, or whether the user/attacker flushes history at all.
AUDIT_LOG="/var/log/audit/audit.log"
AUDIT_RULE_KEY="hids_recon"
AUDIT_LOG_RULE_KEY="hids_log_integrity"
AUDIT_RULE_FILE="/etc/audit/rules.d/60-hids-recon.rules"

# Creates the project state directories used by the HIDS to store logs and baselines.
ensure_state_dir() {
  mkdir -p "${STATE_DIR}" "${BASELINE_DIR}" "${USER_BEHAVIOR_STATE_DIR}"
  [ -e "${LOG_FILE}" ] || touch "${LOG_FILE}"
}

# Removes append-only protection temporarily so HIDS itself can migrate old log records.
unlock_log_for_maintenance() {
  [ "${HIDS_LOG_APPEND_ONLY:-true}" = "true" ] || return 0
  [ "$(id -u 2>/dev/null || echo 1)" -eq 0 ] || return 0
  command -v chattr >/dev/null 2>&1 || return 0
  [ -f "${LOG_FILE}" ] || return 0
  chattr -a "${LOG_FILE}" 2>/dev/null || true
}

# Hardens the local alert log against non-root modification on Linux.
harden_log_file() {
  [ -f "${LOG_FILE}" ] || return 0
  chmod 0600 "${LOG_FILE}" 2>/dev/null || true
  if [ "$(id -u 2>/dev/null || echo 1)" -eq 0 ]; then
    chown root:root "${LOG_FILE}" 2>/dev/null || true
    if [ "${HIDS_LOG_APPEND_ONLY:-true}" = "true" ] && command -v chattr >/dev/null 2>&1; then
      chattr +a "${LOG_FILE}" 2>/dev/null || true
    fi
  fi
}

# Escapes a string for JSON output in the legacy HIDS log format.
json_escape_field() {
  local value="${1:-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/}"
  value="${value//$'\t'/\\t}"
  printf '%s' "${value}"
}

# Extracts a simple JSON string field from one HIDS JSONL event.
json_field_from_line() {
  local field="${1:-}"
  local line="${2:-}"
  if [ "${field}" = "message" ]; then
    printf '%s\n' "${line}" | sed -n 's/.*"message":"\(.*\)"}$/\1/p'
    return 0
  fi
  printf '%s\n' "${line}" | sed -n 's/.*"'"${field}"'":"\([^"]*\)".*/\1/p'
}

# Hashes one alert's ID, original timestamp, severity, module, message, and previous hash.
alert_event_hash() {
  local alert_id="${1:-}"
  local timestamp="${2:-}"
  local severity="${3:-}"
  local module="${4:-}"
  local json_message="${5:-}"
  local prev_hash="${6:-${ZERO_HASH}}"
  printf '%s' "${alert_id}|${timestamp}|${severity}|${module}|${json_message}|${prev_hash}" | sha256sum | awk '{print $1}'
}

# Returns the latest hash-chain tip from the log.
last_event_hash() {
  local hash
  hash="$(sed -n 's/.*"event_hash":"\([a-f0-9][a-f0-9]*\)".*/\1/p' "${LOG_FILE}" 2>/dev/null | tail -n 1)"
  if [ -n "${hash}" ]; then
    printf '%s' "${hash}"
  else
    printf '%s' "${ZERO_HASH}"
  fi
}

# Adds monotonically increasing IDs to pre-existing log lines that do not have one.
migrate_alert_ids() {
  [ -f "${LOG_FILE}" ] || return 0
  if ! grep -vq '"id":"[0-9][0-9]*"' "${LOG_FILE}" 2>/dev/null && \
    ! grep -vq '"event_hash":"[a-f0-9][a-f0-9]*"' "${LOG_FILE}" 2>/dev/null; then
    return 0
  fi

  local tmp_file next_id line existing_id max_existing_id chain_hash event_hash timestamp severity module json_message
  tmp_file="$(mktemp)"
  chain_hash="${ZERO_HASH}"
  max_existing_id="$(sed -n 's/.*"id":"\([0-9][0-9]*\)".*/\1/p' "${LOG_FILE}" 2>/dev/null | sort -n | tail -n 1)"
  if [ -n "${max_existing_id}" ]; then
    next_id=$((10#${max_existing_id} + 1))
  else
    next_id=1
  fi
  while IFS= read -r line || [ -n "${line}" ]; do
    [ -z "${line}" ] && continue
    if printf '%s\n' "${line}" | grep -q '"id":"[0-9][0-9]*"'; then
      printf '%s\n' "${line}" >> "${tmp_file}"
      existing_id="$(printf '%s\n' "${line}" | sed -n 's/.*"id":"\([0-9][0-9]*\)".*/\1/p')"
      existing_id=$((10#${existing_id}))
      if [ "${existing_id}" -ge "${next_id}" ]; then
        next_id=$((existing_id + 1))
      fi
    else
      printf '%s\n' "${line}" | sed "s/^{/{\"id\":\"$(printf '%06d' "${next_id}")\",/" >> "${tmp_file}"
      line="$(tail -n 1 "${tmp_file}")"
      next_id=$((next_id + 1))
    fi
    if printf '%s\n' "${line}" | grep -q '"event_hash":"[a-f0-9][a-f0-9]*"'; then
      chain_hash="$(json_field_from_line event_hash "${line}")"
    else
      existing_id="$(json_field_from_line id "${line}")"
      timestamp="$(json_field_from_line timestamp "${line}")"
      severity="$(json_field_from_line severity "${line}")"
      module="$(json_field_from_line module "${line}")"
      json_message="$(json_field_from_line message "${line}")"
      event_hash="$(alert_event_hash "${existing_id}" "${timestamp}" "${severity}" "${module}" "${json_message}" "${chain_hash}")"
      sed -i '$d' "${tmp_file}"
      printf '%s\n' "${line}" | sed "s/\"id\":\"${existing_id}\"/\"id\":\"${existing_id}\",\"prev_hash\":\"${chain_hash}\",\"event_hash\":\"${event_hash}\"/" >> "${tmp_file}"
      chain_hash="${event_hash}"
    fi
  done < "${LOG_FILE}"
  mv "${tmp_file}" "${LOG_FILE}"
}

# Returns the next alert ID, padded to at least six digits for readability.
next_alert_id() {
  local max_id
  max_id="$(sed -n 's/.*"id":"\([0-9][0-9]*\)".*/\1/p' "${LOG_FILE}" 2>/dev/null | sort -n | tail -n 1)"
  if [ -z "${max_id}" ]; then
    printf '%s' "000001"
  else
    printf '%06d' "$((10#${max_id} + 1))"
  fi
}

# Returns success when the same alert has already been logged, preserving its original ID/timestamp.
alert_already_logged() {
  local severity="${1:-}"
  local module="${2:-}"
  local json_message="${3:-}"
  grep -F '"severity":"'"${severity}"'"' "${LOG_FILE}" 2>/dev/null | \
    grep -F '"module":"'"${module}"'"' | \
    grep -F '"message":"'"${json_message}"'"' >/dev/null 2>&1
}

# Records a timestamped alert in the persistent log file with severity and module metadata.
log_event() {
  local severity="${1:-LOW}"
  local module="${2:-general}"
  local message="${3:-No message provided}"
  ensure_state_dir
  unlock_log_for_maintenance
  migrate_alert_ids
  local stamp
  stamp="$(date '+%Y-%m-%d %H:%M:%S %Z')"
  local json_message
  json_message="$(json_escape_field "${message}")"
  if alert_already_logged "${severity}" "${module}" "${json_message}"; then
    return 0
  fi
  local alert_id
  alert_id="$(next_alert_id)"
  local prev_hash event_hash
  prev_hash="$(last_event_hash)"
  event_hash="$(alert_event_hash "${alert_id}" "${stamp}" "${severity}" "${module}" "${json_message}" "${prev_hash}")"
  printf '{"id":"%s","prev_hash":"%s","event_hash":"%s","timestamp":"%s","severity":"%s","module":"%s","message":"%s"}\n' "${alert_id}" "${prev_hash}" "${event_hash}" "${stamp}" "${severity}" "${module}" "${json_message}" >> "${LOG_FILE}"
  harden_log_file
}

# Verifies alert IDs and the hash chain so tampering is visible during audits.
verify_log_integrity() {
  ensure_state_dir
  local expected_prev="${ZERO_HASH}"
  local line_number=0 failures=0 line alert_id prev_hash event_hash timestamp severity module json_message expected_hash previous_id=0 numeric_id

  while IFS= read -r line || [ -n "${line}" ]; do
    [ -z "${line}" ] && continue
    line_number=$((line_number + 1))
    alert_id="$(json_field_from_line id "${line}")"
    prev_hash="$(json_field_from_line prev_hash "${line}")"
    event_hash="$(json_field_from_line event_hash "${line}")"
    timestamp="$(json_field_from_line timestamp "${line}")"
    severity="$(json_field_from_line severity "${line}")"
    module="$(json_field_from_line module "${line}")"
    json_message="$(json_field_from_line message "${line}")"

    if ! printf '%s' "${alert_id}" | grep -Eq '^[0-9]+$'; then
      echo "Line ${line_number}: missing or invalid alert id" >&2
      failures=$((failures + 1))
      continue
    fi
    numeric_id=$((10#${alert_id}))
    if [ "${numeric_id}" -le "${previous_id}" ]; then
      echo "Line ${line_number}: alert id ${alert_id} is not strictly increasing" >&2
      failures=$((failures + 1))
    fi
    previous_id="${numeric_id}"

    if [ "${prev_hash}" != "${expected_prev}" ]; then
      echo "Line ${line_number}: previous hash mismatch for alert ${alert_id}" >&2
      failures=$((failures + 1))
    fi
    expected_hash="$(alert_event_hash "${alert_id}" "${timestamp}" "${severity}" "${module}" "${json_message}" "${prev_hash}")"
    if [ "${event_hash}" != "${expected_hash}" ]; then
      echo "Line ${line_number}: event hash mismatch for alert ${alert_id}" >&2
      failures=$((failures + 1))
    fi
    expected_prev="${event_hash}"
  done < "${LOG_FILE}"

  if [ "${failures}" -eq 0 ]; then
    echo "HIDS log integrity verified: IDs and hash chain are intact."
    return 0
  fi
  echo "HIDS log integrity verification failed with ${failures} issue(s)." >&2
  return 1
}

# Module 1: checks if the system is currently healthy by reviewing CPU, memory, and disk usage.
module_system_health() {
  local cpu_usage=0
  local mem_used=0
  local mem_total=0
  local disk_usage=0
  local load_avg=""

  # Load persisted counters from the previous run so rate/delta metrics (iowait, TCP
  # retransmits, swap activity) are meaningful across separate cron invocations.
  local prev_cpu_total=0 prev_cpu_idle=0 prev_cpu_iowait=0
  local prev_tcp_out=0 prev_tcp_retrans=0
  local prev_pswpin=0 prev_pswpout=0 prev_swap_active=0
  if [ -f "${HEALTH_STATE_FILE}" ]; then
    # shellcheck disable=SC1090
    source "${HEALTH_STATE_FILE}"
    prev_cpu_total="${PREV_CPU_TOTAL:-0}"
    prev_cpu_idle="${PREV_CPU_IDLE:-0}"
    prev_cpu_iowait="${PREV_CPU_IOWAIT:-0}"
    prev_tcp_out="${PREV_TCP_OUT:-0}"
    prev_tcp_retrans="${PREV_TCP_RETRANS:-0}"
    prev_pswpin="${PREV_PSWPIN:-0}"
    prev_pswpout="${PREV_PSWPOUT:-0}"
    prev_swap_active="${PREV_SWAP_ACTIVE:-0}"
  fi

  if [ -r /proc/stat ]; then
    local cpu_line
    cpu_line="$(grep '^cpu ' /proc/stat 2>/dev/null)"
    if [ -n "${cpu_line}" ]; then
      read -r _ a b c d e f g h i j <<< "${cpu_line}"
      local idle_now=$((d + e))
      local total_now=$((a + b + c + d + e + f + g + h + i + j))

      if [ "${prev_cpu_total}" -gt 0 ]; then
        local total_delta=$((total_now - prev_cpu_total))
        local idle_delta=$((idle_now - prev_cpu_idle))
        if [ "${total_delta}" -gt 0 ]; then
          cpu_usage=$((100 * (total_delta - idle_delta) / total_delta))
        fi
      fi
      PREV_CPU_TOTAL="${total_now}"
      PREV_CPU_IDLE="${idle_now}"
      PREV_CPU_IOWAIT="${e}"
    fi
  fi

  # Metric 1: CPU I/O wait percentage (time spent waiting on disk/storage).
  local iowait_pct=""
  if [ -r /proc/stat ] && [ -n "${cpu_line:-}" ] && [ "${prev_cpu_total}" -gt 0 ]; then
    local total_now_iowait="${PREV_CPU_TOTAL}"
    local iowait_delta=$((PREV_CPU_IOWAIT - prev_cpu_iowait))
    local total_delta_iowait=$((total_now_iowait - prev_cpu_total))
    if [ "${total_delta_iowait}" -gt 0 ]; then
      iowait_pct=$((100 * iowait_delta / total_delta_iowait))
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

  # Metric 2: system load average (1-minute) normalized per CPU core.
  local load1="" cores="" load_per_core=""
  if [ -r /proc/loadavg ]; then
    load1="$(awk '{print $1}' /proc/loadavg 2>/dev/null)"
  fi
  cores="$(command -v nproc >/dev/null 2>&1 && nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 1)"
  if [ -n "${load1}" ] && [ -n "${cores}" ] && [ "${cores}" -gt 0 ] 2>/dev/null; then
    load_per_core="$(awk -v l="${load1}" -v c="${cores}" 'BEGIN{printf "%.2f", l/c}')"
  fi

  # Metric 3: disk space usage (already collected above as disk_usage).

  # Metric 4: inode usage on the root filesystem.
  local inode_usage=""
  if command -v df >/dev/null 2>&1; then
    inode_usage="$(df -iP / 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%')"
  fi

  # Metric 5: storage device await latency (SSD vs HDD thresholds), best-effort via iostat.
  local await_ms="" await_threshold="" await_label=""
  if command -v iostat >/dev/null 2>&1; then
    local root_dev base_dev rotational
    root_dev="$(df -P / 2>/dev/null | awk 'NR==2 {print $1}')"
    base_dev="$(basename "${root_dev}" 2>/dev/null | sed -E 's/p?[0-9]+$//')"
    if [ -n "${base_dev}" ] && [ -r "/sys/block/${base_dev}/queue/rotational" ]; then
      rotational="$(cat "/sys/block/${base_dev}/queue/rotational" 2>/dev/null || echo 1)"
      if [ "${rotational}" = "0" ]; then
        await_threshold="${HEALTH_SSD_AWAIT_MS}"
        await_label="SSD"
      else
        await_threshold="${HEALTH_HDD_AWAIT_MS}"
        await_label="HDD"
      fi
      await_ms="$(iostat -x -d "${base_dev}" 1 2 2>/dev/null | awk -v dev="${base_dev}" '
        /Device/ { for (i=1;i<=NF;i++) if ($i=="await") col=i; header_seen++ }
        $1==dev && header_seen==2 { print $col }
      ')"
    fi
  fi

  # Metric 6: TCP retransmit rate, derived from cumulative /proc/net/snmp counters.
  local tcp_retrans_pct=""
  if [ -r /proc/net/snmp ]; then
    local tcp_out_now tcp_retrans_now
    tcp_out_now="$(awk '/^Tcp:/{for(i=1;i<=NF;i++) if(h[i]=="OutSegs") print $i} /^Tcp:/ && !h_done {for(i=1;i<=NF;i++) h[i]=$i; h_done=1}' /proc/net/snmp 2>/dev/null | tail -n 1)"
    tcp_retrans_now="$(awk '/^Tcp:/{for(i=1;i<=NF;i++) if(h[i]=="RetransSegs") print $i} /^Tcp:/ && !h_done {for(i=1;i<=NF;i++) h[i]=$i; h_done=1}' /proc/net/snmp 2>/dev/null | tail -n 1)"
    if [ -n "${tcp_out_now}" ] && [ -n "${tcp_retrans_now}" ] && [ "${prev_tcp_out}" -gt 0 ] 2>/dev/null; then
      local out_delta=$((tcp_out_now - prev_tcp_out))
      local retrans_delta=$((tcp_retrans_now - prev_tcp_retrans))
      if [ "${out_delta}" -gt 0 ]; then
        tcp_retrans_pct="$(awk -v r="${retrans_delta}" -v o="${out_delta}" 'BEGIN{printf "%.2f", 100*r/o}')"
      fi
    fi
    PREV_TCP_OUT="${tcp_out_now:-0}"
    PREV_TCP_RETRANS="${tcp_retrans_now:-0}"
  fi

  # Metric 7: file descriptor usage relative to the system-wide max.
  local fd_usage_pct=""
  if [ -r /proc/sys/fs/file-nr ]; then
    local fd_allocated fd_max
    read -r fd_allocated _ fd_max < /proc/sys/fs/file-nr 2>/dev/null
    if [ -n "${fd_allocated}" ] && [ -n "${fd_max}" ] && [ "${fd_max}" -gt 0 ]; then
      fd_usage_pct="$(awk -v a="${fd_allocated}" -v m="${fd_max}" 'BEGIN{printf "%.1f", 100*a/m}')"
    fi
  fi

  # Metric 8: CPU temperature (best-effort; not available on many VMs/cloud hosts).
  local cpu_temp_c=""
  if compgen -G "/sys/class/thermal/thermal_zone*/temp" >/dev/null 2>&1; then
    cpu_temp_c="$(cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null | awk 'BEGIN{max=0} {v=$1/1000; if (v>max) max=v} END{if (NR>0) printf "%.1f", max}')"
  fi

  # Metric 9: swap in/out activity, flagged only if sustained across two consecutive checks.
  local swap_active_now=0 swap_sustained=0
  if [ -r /proc/vmstat ]; then
    local pswpin_now pswpout_now
    pswpin_now="$(awk '/^pswpin /{print $2}' /proc/vmstat 2>/dev/null)"
    pswpout_now="$(awk '/^pswpout /{print $2}' /proc/vmstat 2>/dev/null)"
    if [ -n "${pswpin_now}" ] && [ -n "${pswpout_now}" ] && [ "${prev_pswpin}" -gt 0 ] 2>/dev/null; then
      local swpin_delta=$((pswpin_now - prev_pswpin))
      local swpout_delta=$((pswpout_now - prev_pswpout))
      if [ "${swpin_delta}" -gt 0 ] || [ "${swpout_delta}" -gt 0 ]; then
        swap_active_now=1
        if [ "${prev_swap_active}" -eq 1 ]; then
          swap_sustained=1
        fi
      fi
    fi
    PREV_PSWPIN="${pswpin_now:-0}"
    PREV_PSWPOUT="${pswpout_now:-0}"
    PREV_SWAP_ACTIVE="${swap_active_now}"
  fi

  # Persist counters for the next run's delta/rate calculations.
  {
    printf 'PREV_CPU_TOTAL=%s\n' "${PREV_CPU_TOTAL:-0}"
    printf 'PREV_CPU_IDLE=%s\n' "${PREV_CPU_IDLE:-0}"
    printf 'PREV_CPU_IOWAIT=%s\n' "${PREV_CPU_IOWAIT:-0}"
    printf 'PREV_TCP_OUT=%s\n' "${PREV_TCP_OUT:-0}"
    printf 'PREV_TCP_RETRANS=%s\n' "${PREV_TCP_RETRANS:-0}"
    printf 'PREV_PSWPIN=%s\n' "${PREV_PSWPIN:-0}"
    printf 'PREV_PSWPOUT=%s\n' "${PREV_PSWPOUT:-0}"
    printf 'PREV_SWAP_ACTIVE=%s\n' "${PREV_SWAP_ACTIVE:-0}"
  } > "${HEALTH_STATE_FILE}"

  # Score how many of the monitored metrics exceed their warning thresholds.
  local exceeded_count=0
  local exceeded_list=()
  local skipped_list=()

  if [ -n "${iowait_pct}" ]; then
    [ "${iowait_pct}" -gt "${HEALTH_IOWAIT_THRESHOLD}" ] 2>/dev/null && { exceeded_count=$((exceeded_count + 1)); exceeded_list+=("CPU I/O wait ${iowait_pct}% > ${HEALTH_IOWAIT_THRESHOLD}%"); }
  else
    skipped_list+=("CPU I/O wait (no prior sample yet)")
  fi

  if [ -n "${load_per_core}" ]; then
    if awk -v v="${load_per_core}" -v t="${HEALTH_LOAD_PER_CORE_THRESHOLD}" 'BEGIN{exit !(v>t)}'; then
      exceeded_count=$((exceeded_count + 1)); exceeded_list+=("Load per core ${load_per_core} > ${HEALTH_LOAD_PER_CORE_THRESHOLD}")
    fi
  else
    skipped_list+=("Load per core (unavailable)")
  fi

  if [ -n "${disk_usage}" ]; then
    [ "${disk_usage}" -gt "${HEALTH_DISK_THRESHOLD}" ] 2>/dev/null && { exceeded_count=$((exceeded_count + 1)); exceeded_list+=("Disk usage ${disk_usage}% > ${HEALTH_DISK_THRESHOLD}%"); }
  else
    skipped_list+=("Disk usage (unavailable)")
  fi

  if [ -n "${inode_usage}" ]; then
    [ "${inode_usage}" -gt "${HEALTH_INODE_THRESHOLD}" ] 2>/dev/null && { exceeded_count=$((exceeded_count + 1)); exceeded_list+=("Inode usage ${inode_usage}% > ${HEALTH_INODE_THRESHOLD}%"); }
  else
    skipped_list+=("Inode usage (unavailable)")
  fi

  if [ -n "${await_ms}" ] && [ -n "${await_threshold}" ]; then
    if awk -v v="${await_ms}" -v t="${await_threshold}" 'BEGIN{exit !(v>t)}'; then
      exceeded_count=$((exceeded_count + 1)); exceeded_list+=("${await_label} await ${await_ms}ms > ${await_threshold}ms")
    fi
  else
    skipped_list+=("Disk await (iostat not available)")
  fi

  if [ -n "${tcp_retrans_pct}" ]; then
    if awk -v v="${tcp_retrans_pct}" -v t="${HEALTH_TCP_RETRANS_PCT}" 'BEGIN{exit !(v>t)}'; then
      exceeded_count=$((exceeded_count + 1)); exceeded_list+=("TCP retransmit rate ${tcp_retrans_pct}% > ${HEALTH_TCP_RETRANS_PCT}%")
    fi
  else
    skipped_list+=("TCP retransmit rate (no new traffic sampled)")
  fi

  if [ -n "${fd_usage_pct}" ]; then
    if awk -v v="${fd_usage_pct}" -v t="${HEALTH_FD_USAGE_PCT}" 'BEGIN{exit !(v>t)}'; then
      exceeded_count=$((exceeded_count + 1)); exceeded_list+=("File descriptors ${fd_usage_pct}% > ${HEALTH_FD_USAGE_PCT}%")
    fi
  else
    skipped_list+=("File descriptor usage (unavailable)")
  fi

  if [ -n "${cpu_temp_c}" ]; then
    if awk -v v="${cpu_temp_c}" -v t="${HEALTH_CPU_TEMP_C}" 'BEGIN{exit !(v>t)}'; then
      exceeded_count=$((exceeded_count + 1)); exceeded_list+=("CPU temperature ${cpu_temp_c}C > ${HEALTH_CPU_TEMP_C}C")
    fi
  else
    skipped_list+=("CPU temperature (no thermal sensor)")
  fi

  if [ "${swap_sustained}" -eq 1 ]; then
    exceeded_count=$((exceeded_count + 1)); exceeded_list+=("Sustained swap-in/swap-out activity")
  fi

  local metric_summary="CPU=${cpu_usage}% MEM=${mem_used}% DISK=${disk_usage:-0}% LOAD=${load_avg:-unknown}"
  local skipped_note=""
  if [ "${#skipped_list[@]}" -gt 0 ]; then
    skipped_note=" [${#skipped_list[@]} metric(s) unavailable: $(IFS='; '; echo "${skipped_list[*]}")]"
  fi
  if [ "${exceeded_count}" -eq 0 ]; then
    log_event "LOW" "system_health" "${metric_summary}; all monitored health metrics within normal range${skipped_note}"
  else
    local detail
    detail="$(IFS='; '; echo "${exceeded_list[*]}")"
    if [ "${exceeded_count}" -ge "${HEALTH_HIGH_SEVERITY_COUNT}" ]; then
      log_event "HIGH" "system_health" "${exceeded_count} health metrics exceeded thresholds (${metric_summary}): ${detail}${skipped_note}"
    else
      log_event "MEDIUM" "system_health" "${exceeded_count} health metric(s) exceeded thresholds (${metric_summary}): ${detail}${skipped_note}"
    fi
  fi
}

# Collects recent failed login attempts from the sources commonly available on Linux VMs.
collect_failed_login_events() {
  local failures=""

  if command -v lastb >/dev/null 2>&1; then
    failures="$(lastb -n 20 -a -w 2>/dev/null | grep -v '^$' | grep -v '^wtmp' | grep -v '^btmp' || true)"
    if [ -n "${failures}" ]; then
      printf '%s\n' "${failures}"
      return 0
    fi
  fi

  local auth_log
  for auth_log in "${AUTH_LOG_CANDIDATES[@]}"; do
    if [ -r "${auth_log}" ]; then
      failures="$(grep -Ei 'sshd.*(Failed password|Invalid user|authentication failure|Failed publickey)|authentication failure.*sshd' "${auth_log}" 2>/dev/null | tail -n 20 || true)"
      if [ -n "${failures}" ]; then
        printf '%s\n' "${failures}"
        return 0
      fi
    fi
  done

  if command -v journalctl >/dev/null 2>&1; then
    failures="$(journalctl -u ssh -u sshd -u ssh.service -u sshd.service --since "${FAILED_LOGIN_WINDOW_MIN} minutes ago" --no-pager 2>/dev/null | grep -Ei 'sshd.*(Failed password|Invalid user|authentication failure|Failed publickey)|authentication failure.*sshd' | tail -n 20 || true)"
    if [ -n "${failures}" ]; then
      printf '%s\n' "${failures}"
      return 0
    fi
  fi

  return 1
}

# Module 2: checks for current and recent user activity to spot abnormal logins or unexpected accounts.
module_user_activity() {
  local current_users
  current_users="$(who 2>/dev/null || true)"
  local recent_logins
  recent_logins="$(last -n 10 2>/dev/null || true)"
  local failed_logins
  failed_logins="$(collect_failed_login_events || true)"

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

# Lists the persistence-related files (cron jobs, SSH authorized_keys) tracked for tampering.
list_persistence_targets() {
  {
    [ -f /etc/crontab ] && echo /etc/crontab
    if [ -d /etc/cron.d ]; then find /etc/cron.d -maxdepth 1 -type f 2>/dev/null; fi
    for keyfile in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
      [ -f "${keyfile}" ] && echo "${keyfile}"
    done
  } | sort -u
}

# Installs auditd watch rules on prohibited executables and the HIDS log so security-relevant
# activity is logged by the kernel in real time, regardless of shell history settings.
install_audit_rules() {
  if ! command -v auditctl >/dev/null 2>&1; then
    echo "auditd is not installed. Install it for tamper-resistant command detection (works even if a user disables shell history):"
    echo "  sudo apt install -y auditd"
    echo "  sudo ./HIDS.sh --install-audit-rules"
    return 1
  fi
  if [ "$(id -u)" -ne 0 ]; then
    echo "Installing audit rules requires root. Re-run as: sudo ./HIDS.sh --install-audit-rules"
    return 1
  fi

  mkdir -p /etc/audit/rules.d
  ensure_state_dir
  harden_log_file
  : > "${AUDIT_RULE_FILE}"
  local watch_bin
  for watch_bin in /usr/bin/whoami /bin/whoami /usr/bin/id /bin/id /usr/bin/uname /bin/uname /usr/bin/find /bin/find /usr/bin/rm /bin/rm /usr/bin/shred /bin/shred /usr/bin/unlink /bin/unlink /usr/bin/truncate /bin/truncate; do
    if [ -e "${watch_bin}" ]; then
      printf -- '-w %s -p x -k %s\n' "${watch_bin}" "${AUDIT_RULE_KEY}" >> "${AUDIT_RULE_FILE}"
    fi
  done
  printf -- '-w %s -p wa -k %s\n' "${LOG_FILE}" "${AUDIT_LOG_RULE_KEY}" >> "${AUDIT_RULE_FILE}"

  if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1
  else
    auditctl -R "${AUDIT_RULE_FILE}" >/dev/null 2>&1
  fi
  systemctl enable --now auditd >/dev/null 2>&1 || service auditd restart >/dev/null 2>&1 || true

  log_event "LOW" "scheduler" "auditd rules installed for recon commands and HIDS log tamper monitoring (keys=${AUDIT_RULE_KEY},${AUDIT_LOG_RULE_KEY})"
  echo "auditd rules installed. Recon command execution and HIDS log write/attribute changes are now logged to ${AUDIT_LOG}."
}

# Lists shell command history files to scan (bash history for all local users).
list_shell_history_files() {
  {
    for hist_file in /root/.bash_history /home/*/.bash_history; do
      [ -f "${hist_file}" ] && echo "${hist_file}"
    done
  } | sort -u
}

# Flags reconnaissance and history-tampering commands seen in running processes or new shell history lines.
# Repeated identical commands within the same scan are collapsed into a single "Nx <command>" count.
check_recon_commands() {
  local matched_lines=()
  local fresh_command_matches=()
  local proc_line observed_at
  observed_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  while IFS= read -r proc_line; do
    [ -z "${proc_line}" ] && continue
    if printf '%s' "${proc_line}" | grep -Eq "${RECON_COMMAND_REGEX}" || printf '%s' "${proc_line}" | grep -Eq "${SUID_SCAN_REGEX}" || printf '%s' "${proc_line}" | grep -Eq "${HISTORY_TAMPER_REGEX}"; then
      matched_lines+=("[observed ${observed_at}] ${proc_line}")
    fi
  done < <(ps -eo command --no-headers 2>/dev/null)

  local hist_file
  while IFS= read -r hist_file; do
    [ -f "${hist_file}" ] || continue
    local key state_file last_count total_count new_lines matched matched_line
    key="$(printf '%s' "${hist_file}" | tr -c 'A-Za-z0-9' '_')"
    state_file="${USER_BEHAVIOR_STATE_DIR}/hist_${key}.count"
    last_count=0
    [ -f "${state_file}" ] && last_count="$(cat "${state_file}" 2>/dev/null || echo 0)"
    total_count="$(wc -l < "${hist_file}" 2>/dev/null || echo 0)"
    if [ "${total_count}" -gt "${last_count}" ]; then
      new_lines="$(tail -n +"$((last_count + 1))" "${hist_file}" 2>/dev/null)"
      matched="$(printf '%s\n' "${new_lines}" | grep -E "${RECON_COMMAND_REGEX}|${SUID_SCAN_REGEX}|${HISTORY_TAMPER_REGEX}" || true)"
      if [ -n "${matched}" ]; then
        while IFS= read -r matched_line; do
          [ -z "${matched_line}" ] && continue
          matched_lines+=("[observed ${observed_at}] ${matched_line}")
          fresh_command_matches+=("[observed ${observed_at}] ${matched_line}")
        done <<< "${matched}"
      fi
    fi
    printf '%s\n' "${total_count}" > "${state_file}" 2>/dev/null || true
  done < <(list_shell_history_files)

  # auditd (if installed via --install-audit-rules) catches execution even if shell history is disabled.
  if [ -r "${AUDIT_LOG}" ]; then
    local audit_key audit_state_file audit_last_offset audit_total_lines audit_new_lines audit_matches audit_line exe_path audit_command audit_target audit_timestamp
    audit_key="$(printf '%s' "${AUDIT_LOG}" | tr -c 'A-Za-z0-9' '_')"
    audit_state_file="${USER_BEHAVIOR_STATE_DIR}/audit_${audit_key}.offset"
    audit_last_offset=0
    [ -f "${audit_state_file}" ] && audit_last_offset="$(cat "${audit_state_file}" 2>/dev/null || echo 0)"
    audit_total_lines="$(wc -l < "${AUDIT_LOG}" 2>/dev/null || echo 0)"
    if [ "${audit_total_lines}" -lt "${audit_last_offset}" ]; then
      audit_last_offset=0
    fi
    if [ "${audit_total_lines}" -gt "${audit_last_offset}" ]; then
      audit_new_lines="$(tail -n +"$((audit_last_offset + 1))" "${AUDIT_LOG}" 2>/dev/null)"
      audit_matches="$(printf '%s\n' "${audit_new_lines}" | grep -E 'name="(/usr/bin/whoami|/bin/whoami|/usr/bin/id|/bin/id|/usr/bin/uname|/bin/uname|/usr/bin/find|/bin/find)"|type=EXECVE.*a0="(rm|shred|unlink|truncate)".*(\.bash_history|\.zsh_history|\.sh_history)' || true)"
      if [ -n "${audit_matches}" ]; then
        while IFS= read -r audit_line; do
          [ -z "${audit_line}" ] && continue
          exe_path="$(printf '%s\n' "${audit_line}" | grep -oE 'name="(/usr/bin/whoami|/bin/whoami|/usr/bin/id|/bin/id|/usr/bin/uname|/bin/uname|/usr/bin/find|/bin/find)"' | head -n 1 | sed -E 's/^name="//; s/"$//')"
          if [ -z "${exe_path}" ]; then
            audit_command="$(printf '%s\n' "${audit_line}" | sed -nE 's/.*a0="(rm|shred|unlink|truncate)".*/\1/p' | head -n 1)"
            audit_target="$(printf '%s\n' "${audit_line}" | grep -oE '([^"[:space:]]*/|~/)?\.(bash|zsh|sh)_history' | head -n 1)"
            if [ -z "${audit_command}" ] || [ -z "${audit_target}" ]; then
              continue
            fi
            exe_path="${audit_command} ${audit_target}"
          fi
          audit_timestamp="$(printf '%s\n' "${audit_line}" | sed -nE 's/.*msg=audit\(([0-9]+)\.[0-9]+:[0-9]+\).*/\1/p' | head -n 1)"
          if [ -n "${audit_timestamp}" ]; then
            audit_timestamp="$(date -u -d "@${audit_timestamp}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf '%s' "${audit_timestamp}")"
          else
            audit_timestamp="${observed_at}"
          fi
          matched_lines+=("[audit-exec ${audit_timestamp}] ${exe_path}")
          fresh_command_matches+=("[audit-exec ${audit_timestamp}] ${exe_path}")
        done <<< "${audit_matches}"
      fi
    fi
    printf '%s\n' "${audit_total_lines}" > "${audit_state_file}" 2>/dev/null || true
  fi

  if [ "${#matched_lines[@]}" -eq 0 ]; then
    return 1
  fi

  local summary
  summary="$(printf '%s\n' "${matched_lines[@]}" | sort | uniq -c | awk '{count=$1; $1=""; sub(/^ /,""); printf "%dx %s; ", count, $0}')"

  log_event "HIGH" "user_activity" "Prohibited command activity detected (reconnaissance, SUID scan, or history tampering): ${summary}"
  if [ "${#fresh_command_matches[@]}" -gt 0 ]; then
    export HIDS_RECON_COMMAND_DETECTED=1
  fi
  return 0
}

# Flags non-admin accounts running sudo/su repeatedly within a short window, based on auth log entries.
check_privileged_command_frequency() {
  local auth_log=""
  for candidate in "${AUTH_LOG_CANDIDATES[@]}"; do
    if [ -r "${candidate}" ]; then
      auth_log="${candidate}"
      break
    fi
  done
  [ -z "${auth_log}" ] && return 1

  local key offset_file last_offset total_lines new_lines
  key="$(printf '%s' "${auth_log}" | tr -c 'A-Za-z0-9' '_')"
  offset_file="${USER_BEHAVIOR_STATE_DIR}/authlog_${key}.offset"
  last_offset=0
  [ -f "${offset_file}" ] && last_offset="$(cat "${offset_file}" 2>/dev/null || echo 0)"
  total_lines="$(wc -l < "${auth_log}" 2>/dev/null || echo 0)"
  if [ "${total_lines}" -lt "${last_offset}" ]; then
    last_offset=0
  fi
  new_lines="$(tail -n +"$((last_offset + 1))" "${auth_log}" 2>/dev/null)"
  printf '%s\n' "${total_lines}" > "${offset_file}" 2>/dev/null || true
  [ -z "${new_lines}" ] && return 1

  local sudo_lines
  sudo_lines="$(printf '%s\n' "${new_lines}" | grep -E 'sudo:|su\[|su:' || true)"
  [ -z "${sudo_lines}" ] && return 1

  local admin_users
  admin_users="$( (getent group sudo 2>/dev/null; getent group wheel 2>/dev/null; getent group admin 2>/dev/null) | awk -F: '{print $4}' | tr ',' '\n' | sort -u)"

  local flagged="" user
  while IFS= read -r user; do
    [ -z "${user}" ] && continue
    if ! printf '%s\n' "${admin_users}" | grep -qx "${user}"; then
      local count
      count="$(printf '%s\n' "${sudo_lines}" | grep -c -- "${user}")"
      if [ "${count}" -ge "${SUDO_SU_FREQUENCY_THRESHOLD}" ]; then
        flagged+="${user} (${count}x); "
      fi
    fi
  done < <(printf '%s\n' "${sudo_lines}" | grep -oE 'USER=[A-Za-z0-9_.-]+|by [A-Za-z0-9_.-]+' | sed -E 's/USER=|by //' | sort -u)

  if [ -n "${flagged}" ]; then
    log_event "HIGH" "user_activity" "Frequent sudo/su usage by non-admin account(s): ${flagged}"
    return 0
  fi
  return 1
}

# Flags tampering with cron jobs (/etc/crontab, /etc/cron.d) or SSH authorized_keys files.
check_persistence_tampering() {
  [ -f "${BASELINE_DIR}/persistence_hashes.txt" ] || return 1

  local issues=""
  while IFS=$'\t' read -r target digest; do
    [ -z "${target:-}" ] && continue
    if [ ! -e "${target}" ]; then
      issues+="removed: ${target}; "
      continue
    fi
    local current_digest
    current_digest="$(sha256sum "${target}" 2>/dev/null | awk '{print $1}')"
    if [ "${current_digest}" != "${digest}" ]; then
      issues+="modified: ${target}; "
    fi
  done < "${BASELINE_DIR}/persistence_hashes.txt"

  local known_targets current_targets new_targets
  known_targets="$(awk -F'\t' '{print $1}' "${BASELINE_DIR}/persistence_hashes.txt" | LC_ALL=C sort -u)"
  current_targets="$(list_persistence_targets)"
  new_targets="$(comm -13 <(printf '%s\n' "${known_targets}" | LC_ALL=C sort -u) <(printf '%s\n' "${current_targets}" | LC_ALL=C sort -u))"
  if [ -n "${new_targets}" ]; then
    issues+="new persistence file(s): $(printf '%s' "${new_targets}" | tr '\n' ',' ); "
  fi

  if [ -n "${issues}" ]; then
    log_event "HIGH" "user_activity" "Persistence tampering detected in crontab/cron.d/authorized_keys: ${issues}"
    return 0
  fi
  return 1
}

# Flags any shell history file shrink since the last scan, a sign of history clearing or deletion.
check_history_clearing() {
  local hist_file cleared=""
  for hist_file in /root/.bash_history /home/*/.bash_history; do
    local key state_file last_count current_count
    key="$(printf '%s' "${hist_file}" | tr -c 'A-Za-z0-9' '_')"
    state_file="${USER_BEHAVIOR_STATE_DIR}/histsize_${key}.count"
    last_count=0
    [ -f "${state_file}" ] && last_count="$(cat "${state_file}" 2>/dev/null || echo 0)"
    if [ -f "${hist_file}" ]; then
      current_count="$(wc -l < "${hist_file}" 2>/dev/null || echo 0)"
    else
      current_count=0
    fi
    if [ "${last_count}" -gt "${current_count}" ]; then
      cleared+="${hist_file} (was ${last_count} lines, now ${current_count}); "
    fi
    printf '%s\n' "${current_count}" > "${state_file}" 2>/dev/null || true
  done

  if [ -n "${cleared}" ]; then
    log_event "HIGH" "user_activity" "Command history appears to have been cleared: ${cleared}"
    return 0
  fi
  return 1
}

# Flags processes named like well-known system services but running from an unexpected location (masquerading).
check_process_masquerading() {
  local flagged=""
  local pid comm exe sysname
  while IFS= read -r pid; do
    [ -z "${pid}" ] && continue
    comm="$(cat "/proc/${pid}/comm" 2>/dev/null || true)"
    [ -z "${comm}" ] && continue
    for sysname in "${SYSTEM_PROCESS_NAMES[@]}"; do
      if [ "${comm}" = "${sysname}" ]; then
        exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
        if [ -n "${exe}" ] && ! printf '%s' "${exe}" | grep -Eq "${SYSTEM_PROCESS_DIR_REGEX}"; then
          flagged+="PID ${pid} named '${comm}' running from unexpected path ${exe}; "
        fi
        break
      fi
    done
  done < <(ps -eo pid --no-headers 2>/dev/null)

  if [ -n "${flagged}" ]; then
    log_event "HIGH" "user_activity" "Process masquerading as a system service detected: ${flagged}"
    return 0
  fi
  return 1
}

# Module 2.5: runs all insider-threat / post-compromise behavior checks and logs a routine summary if none trigger.
check_insider_threat_activity() {
  ensure_state_dir
  local triggered=0

  check_recon_commands && triggered=1
  check_privileged_command_frequency && triggered=1
  check_persistence_tampering && triggered=1
  check_history_clearing && triggered=1
  check_process_masquerading && triggered=1

  if [ "${triggered}" -eq 0 ]; then
    log_event "LOW" "user_activity" "No insider-threat indicators detected (recon commands, sudo/su abuse, persistence tampering, history clearing, process masquerading)"
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

  : > "${BASELINE_DIR}/persistence_hashes.txt"
  while IFS= read -r target; do
    [ -z "${target}" ] && continue
    local digest
    digest="$(sha256sum "${target}" 2>/dev/null | awk '{print $1}')"
    printf '%s\t%s\n' "${target}" "${digest}" >> "${BASELINE_DIR}/persistence_hashes.txt"
  done < <(list_persistence_targets)

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
  delta="$(comm -13 <(LC_ALL=C sort -u "${BASELINE_DIR}/processes.txt") <(printf '%s\n' "${current_processes}" | LC_ALL=C sort -u))"

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
  delta="$(comm -13 <(LC_ALL=C sort -u "${BASELINE_DIR}/network.txt") <(printf '%s\n' "${current_network}" | LC_ALL=C sort -u))"

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
  delta="$(comm -13 <(LC_ALL=C sort -u "${BASELINE_DIR}/users.txt") <(printf '%s\n' "${current_users}" | LC_ALL=C sort -u))"

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
  delta="$(comm -13 <(LC_ALL=C sort -u "${BASELINE_DIR}/privileged.txt") <(printf '%s\n' "${current_privileged}" | LC_ALL=C sort -u))"

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

  local failed_login_events failed_count
  failed_login_events="$(collect_failed_login_events || true)"
  failed_count="$(printf '%s\n' "${failed_login_events}" | grep -c . 2>/dev/null || true)"
  failed_count="$(echo "${failed_count}" | tr -d ' ')"

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

# Installs a cron entry so the HIDS runs automatically every minute.
install_scheduler() {
  ensure_state_dir

  if [ "$(id -u)" -eq 0 ]; then
    local cron_file="/etc/cron.d/hids-monitor"
    {
      printf '%s\n' "SHELL=/bin/bash"
      printf '%s\n' "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
      printf '%s\n' ""
      printf '%s\n' "# HIDS one-minute scan with threshold-based email alerts"
      printf '* * * * * root bash -c '"'"'cd %s && mkdir -p .hids && set -a && [ -f ./email_config.env ] && . ./email_config.env && set +a && ./HIDS.sh --minute-scan >> .hids/cron.log 2>&1'"'"'\n' "${PROJECT_ROOT}"
    } > "${cron_file}"
    chmod 0644 "${cron_file}"
    log_event "LOW" "scheduler" "Cron job installed at ${cron_file} (one-minute scan)"
    echo "Scheduler installed at ${cron_file}"
  else
    if command -v crontab >/dev/null 2>&1; then
      local user_cron
      user_cron="$(mktemp)"
      crontab -l 2>/dev/null > "${user_cron}" || true
      
      # Remove any existing HIDS cron entries to avoid duplicates
      grep -v "HIDS.sh" "${user_cron}" > "${user_cron}.new" 2>/dev/null || true
      mv "${user_cron}.new" "${user_cron}"
      
      # Add fresh entries
      {
        cat "${user_cron}"
        printf '%s\n' ""
        printf '%s\n' "# HIDS one-minute scan with threshold-based email alerts"
        printf '* * * * * bash -c '"'"'cd %s && mkdir -p .hids && set -a && [ -f ./email_config.env ] && . ./email_config.env && set +a && ./HIDS.sh --minute-scan >> .hids/cron.log 2>&1'"'"'\n' "${PROJECT_ROOT}"
      } > "${user_cron}.final"
      
      crontab "${user_cron}.final"
      rm -f "${user_cron}" "${user_cron}.new" "${user_cron}.final"
      log_event "LOW" "scheduler" "User cron entry installed for ${USER} (one-minute scan)"
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
  ./HIDS.sh --minute-scan
  ./HIDS.sh --instant-check
  ./HIDS.sh --demo
  ./HIDS.sh --install-cron
  ./HIDS.sh --install-audit-rules
  ./HIDS.sh --migrate-log
  ./HIDS.sh --verify-log
  ./HIDS.sh --help

Options:
  --baseline       Create the initial reference snapshot without scanning.
  --once           Run one complete inspection cycle and log any findings.
  --ship-elk       Run one inspection cycle, then ship new events to Elasticsearch.
  --email-report   Run inspection cycle and send an email report if EMAIL_TO is set.
  --minute-scan    Run one inspection cycle and email only for new alert IDs meeting thresholds.
  --instant-check  Run one inspection cycle and ship to Elasticsearch if configured, without sending email.
  --demo           Simulate an attack sequence that triggers log alerts.
  --install-cron   Add a recurring cron job for a one-minute threshold email scan.
  --install-audit-rules  Install auditd watch rules for recon commands and HIDS log tamper
                         monitoring, independent of shell history (requires root; run once).
  --migrate-log    Add alert IDs and hash-chain fields to existing hids.log entries.
  --verify-log     Verify alert IDs and the log hash chain for tampering.
  --help           Show this help menu.
USAGE
}

# Sends an email security report if send_email_report.sh is available.
send_email_after_scan() {
  local email_script="${PROJECT_ROOT}/send_email_report.sh"
  local mode="${1:---scheduled}"
  local lines_count="${2:-30}"

  if [ -f "${email_script}" ]; then
    bash "${email_script}" "${mode}" "${lines_count}"
  fi
}

# Ships new events to Elasticsearch using elk_ship.sh; assumes a scan already ran.
ship_events_to_elk() {
  local ship_script="${PROJECT_ROOT}/elk_ship.sh"

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
  echo "New events shipped to Elasticsearch."
}

# Runs one local scan and then ships new events to Elasticsearch using elk_ship.sh.
ship_after_scan() {
  run_checks

  if ! ship_events_to_elk; then
    return 1
  fi

  if [ -n "${EMAIL_TO:-}" ]; then
    send_email_after_scan --scheduled
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
  export HIDS_RECON_COMMAND_DETECTED=0

  module_system_health
  module_user_activity
  check_brute_force
  check_insider_threat_activity
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
      send_email_after_scan --instant
      ;;
    --minute-scan)
      run_checks
      if [ -n "${EMAIL_TO:-}" ]; then
        send_email_after_scan --minute 5000
      fi
      if [ -n "${ELASTIC_URL:-}" ] && [ -n "${ELASTIC_API_KEY:-}" ]; then
        ship_events_to_elk || true
      fi
      echo "HIDS one-minute scan complete. Results saved in ${LOG_FILE}"
      ;;
    --instant-check)
      run_checks
      if [ -n "${ELASTIC_URL:-}" ] && [ -n "${ELASTIC_API_KEY:-}" ]; then
        ship_events_to_elk || true
      fi
      echo "HIDS instant-alert scan complete. Results saved in ${LOG_FILE}"
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
    --install-audit-rules)
      install_audit_rules
      ;;
    --migrate-log)
      ensure_state_dir
      unlock_log_for_maintenance
      migrate_alert_ids
      harden_log_file
      echo "HIDS log migration complete. Existing entries now include IDs and hash-chain fields where possible."
      ;;
    --verify-log)
      verify_log_integrity
      ;;
    --help|-h)
      print_help
      ;;
    *)
      print_help
      ;;
  esac
}

load_local_environment
main "$@"
