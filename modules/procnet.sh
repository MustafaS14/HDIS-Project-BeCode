#!/usr/bin/env bash
set -uo pipefail

MODULE_DIR="${BASH_SOURCE%/*}"
PROJECT_ROOT="$(cd "${MODULE_DIR}/.." && pwd)"
BASELINE_DIR="${PROJECT_ROOT}/baseline"

if [ -f "${PROJECT_ROOT}/lib/util.sh" ]; then
  source "${PROJECT_ROOT}/lib/util.sh"
fi
if [ -f "${PROJECT_ROOT}/lib/config.sh" ]; then
  source "${PROJECT_ROOT}/lib/config.sh"
  load_config
fi
if [ -f "${PROJECT_ROOT}/lib/alert.sh" ]; then
  source "${PROJECT_ROOT}/lib/alert.sh"
fi
if [ -f "${PROJECT_ROOT}/lib/rules.sh" ]; then
  source "${PROJECT_ROOT}/lib/rules.sh"
fi

# Writes the current listener baseline if it is missing.
ensure_listener_baseline() {
  mkdir -p "${BASELINE_DIR}"
  if [ ! -f "${BASELINE_DIR}/listeners.txt" ]; then
    read_listeners > "${BASELINE_DIR}/listeners.txt"
  fi
}

# Walks /proc/[0-9]* and emits: pid, uid, ppid, resolved exe path, cwd.
enumerate_processes() {
  local proc_dir pid uid ppid comm exe_path cwd_path status_line
  for proc_dir in /proc/[0-9]*; do
    [ -d "${proc_dir}" ] || continue
    pid="${proc_dir##*/}"
    uid=""
    ppid=""
    if [ -r "${proc_dir}/status" ]; then
      uid="$(awk '/^Uid:/ {print $2; exit}' "${proc_dir}/status" 2>/dev/null || true)"
      ppid="$(awk '/^PPid:/ {print $2; exit}' "${proc_dir}/status" 2>/dev/null || true)"
    fi
    comm="$(cat "${proc_dir}/comm" 2>/dev/null || true)"
    exe_path="$(stat -c '%N' "${proc_dir}/exe" 2>/dev/null | awk -F" -> " '{print $NF}' | sed -E "s/^'//; s/'$//" || true)"
    cwd_path="$(stat -c '%N' "${proc_dir}/cwd" 2>/dev/null | awk -F" -> " '{print $NF}' | sed -E "s/^'//; s/'$//" || true)"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "${pid}" "${uid:-0}" "${ppid:-0}" "${comm}" "${exe_path}" "${cwd_path}"
  done
}

# Flags processes running from writable dirs or with deleted binaries.
check_process_paths() {
  local proc_line pid uid ppid comm exe_path cwd_path exe_base writable_dir
  while IFS=$'\t' read -r pid uid ppid comm exe_path cwd_path; do
    [ -z "${pid:-}" ] && continue
    for writable_dir in ${WRITABLE_EXEC_DIRS:-/tmp /var/tmp /dev/shm /run/shm}; do
      case "${exe_path}" in
        "${writable_dir}"/*)
          raise_alert HIGH procnet PRC-001 "Process '${comm}' is running from writable path '${exe_path}'" "pid=${pid} uid=${uid} ppid=${ppid} exe=${exe_path} cwd=${cwd_path}"
          break
          ;;
      esac
    done
    if printf '%s' "${exe_path}" | grep -Fq '(deleted)'; then
      raise_alert HIGH procnet PRC-002 "Process '${comm}' executable was deleted from disk" "pid=${pid} uid=${uid} ppid=${ppid} exe=${exe_path} cwd=${cwd_path}"
    fi

    case "${comm}" in
      [[]*[]])
        if [ -n "${exe_path}" ] && ! printf '%s' "${exe_path}" | grep -Fq '(deleted)'; then
          raise_alert CRITICAL procnet PRC-004 "Bracketed process '${comm}' has a real executable '${exe_path}'" "pid=${pid} uid=${uid} ppid=${ppid} exe=${exe_path} cwd=${cwd_path}"
        fi
        ;;
    esac

    exe_base="${exe_path##*/}"
    case " ${SUSPICIOUS_BINARIES:-nc ncat socat nmap masscan} " in
      *" ${exe_base} "*)
        raise_alert MEDIUM procnet PRC-009 "Suspicious binary '${exe_base}' is running" "pid=${pid} uid=${uid} ppid=${ppid} exe=${exe_path} cwd=${cwd_path}"
        ;;
    esac

    case "${exe_base}" in
      bash|sh|zsh|dash|fish|ksh|csh|tcsh)
        if [ "${uid:-0}" -ge 100 ] && [ "${uid:-0}" -ne 0 ]; then
          raise_alert CRITICAL procnet PRC-006 "Service account UID ${uid} is running an interactive shell '${exe_base}'" "pid=${pid} uid=${uid} ppid=${ppid} exe=${exe_path} cwd=${cwd_path}"
        fi
        ;;
    esac

    case "${uid:-0}" in
      0)
        local parent_comm
        parent_comm="$(ps -p "${ppid}" -o comm= 2>/dev/null | awk 'NR==1 {print $1}' || true)"
        case " ${parent_comm} " in
          *" bash "*|*" sh "*|*" zsh "*|*" dash "*|*" fish "*|*" httpd "*|*" apache2 "*|*" nginx "*|*" php-fpm "*)
            raise_alert HIGH procnet PRC-003 "Root process '${comm}' is parented by '${parent_comm}'" "pid=${pid} uid=${uid} ppid=${ppid} parent=${parent_comm} exe=${exe_path} cwd=${cwd_path}"
            ;;
        esac
        ;;
    esac
  done < <(enumerate_processes)
}

# Compares ls /proc against ps output to find hidden PIDs.
check_hidden_processes() {
  local -A ps_pids seen_pids
  local pid proc_dir

  while IFS= read -r pid; do
    [ -z "${pid}" ] && continue
    ps_pids["${pid}"]=1
  done < <(ps -eo pid= 2>/dev/null | awk '{print $1}')

  for proc_dir in /proc/[0-9]*; do
    [ -d "${proc_dir}" ] || continue
    pid="${proc_dir##*/}"
    seen_pids["${pid}"]=1
    if [ -z "${ps_pids[${pid}]:-}" ]; then
      raise_alert CRITICAL procnet PRC-005 "PID ${pid} is present in /proc but missing from ps output" "pid=${pid}"
    fi
  done
}

# Normalises listeners to "proto address:port" — no PIDs — and diffs baseline.
read_listeners() {
  {
    ss -H -ltn 2>/dev/null || true
    ss -H -lun 2>/dev/null || true
  } | awk 'NF >= 4 {print $1 " " $4}'
}

# Checks listeners against the stored baseline.
check_listeners() {
  ensure_listener_baseline
  local baseline_file current_line proto address_port address port listener_key
  baseline_file="${BASELINE_DIR}/listeners.txt"

  while IFS= read -r current_line; do
    [ -z "${current_line}" ] && continue
    if ! grep -Fxq "${current_line}" "${baseline_file}" 2>/dev/null; then
      proto="${current_line%% *}"
      address_port="${current_line#* }"
      address="${address_port%:*}"
      port="${address_port##*:}"
      if [ -n "${ALLOWED_LISTEN_PORTS:-}" ] && ! printf ' %s ' "${ALLOWED_LISTEN_PORTS}" | grep -Fq " ${port} "; then
        raise_alert HIGH procnet NET-001 "New listener ${current_line} is not on the whitelist" "listener=${current_line}"
      fi
      if [ "${address}" = "0.0.0.0" ] || [ "${address}" = "[::]" ] || [ "${address}" = "*" ]; then
        if ! printf ' %s ' "${ALLOWED_LISTEN_PORTS}" | grep -Fq " ${port} "; then
          raise_alert HIGH procnet NET-002 "Listener ${current_line} is bound to all interfaces" "listener=${current_line}"
        fi
      fi
    fi
  done < <(read_listeners)
}

# Flags interfaces that are in promiscuous mode.
check_promiscuous_mode() {
  if ip link 2>/dev/null | grep -i 'promisc' >/dev/null 2>&1; then
    raise_alert HIGH procnet NET-005 "An interface is in promiscuous mode" "details=$(ip link 2>/dev/null | grep -i 'promisc' | awk 'NR==1 {print}')"
  fi
}

# Orchestrates all of the above.
run_procnet_module() {
  ensure_listener_baseline
  check_process_paths
  check_hidden_processes
  check_listeners
  check_promiscuous_mode
}