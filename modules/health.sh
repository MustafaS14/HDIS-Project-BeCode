#!/usr/bin/env bash
set -uo pipefail

MODULE_DIR="${BASH_SOURCE%/*}"
PROJECT_ROOT="$(cd "${MODULE_DIR}/.." && pwd)"

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

# Reads a cpu snapshot as idle and total jiffies.
read_cpu_snapshot() {
  awk '/^cpu /{idle=$5+$6; total=0; for (i=2; i<=NF; i++) total+=$i; print idle, total}' /proc/stat
}

# Samples /proc/stat twice one second apart and returns CPU busy percentage.
read_cpu_pct() {
  local idle1 total1 idle2 total2 busy_delta total_delta cpu_pct
  read -r idle1 total1 < <(read_cpu_snapshot)
  sleep 1
  read -r idle2 total2 < <(read_cpu_snapshot)
  busy_delta=$(( (total2 - total1) - (idle2 - idle1) ))
  total_delta=$(( total2 - total1 ))
  if [ "${total_delta}" -le 0 ]; then
    printf '0'
    return 0
  fi
  cpu_pct=$(( 100 * busy_delta / total_delta ))
  if [ "${cpu_pct}" -lt 0 ]; then
    cpu_pct=0
  fi
  printf '%s' "${cpu_pct}"
}

# Counts CPU cores from /proc/cpuinfo.
count_cores() {
  local cores
  cores="$(awk '/^processor[[:space:]]*:/ {count++} END {print count+0}' /proc/cpuinfo 2>/dev/null)"
  if [ -z "${cores}" ] || [ "${cores}" -lt 1 ]; then
    cores=1
  fi
  printf '%s' "${cores}"
}

# Returns 1-minute load average divided by the core count, to 2 decimals.
read_load_per_core() {
  local load cores
  load="$(awk '{print $1}' /proc/loadavg 2>/dev/null)"
  cores="$(count_cores)"
  awk -v avg="${load:-0}" -v cores="${cores:-1}" 'BEGIN { if (cores <= 0) cores = 1; printf "%.2f", avg / cores }'
}

# Returns memory usage percentage from /proc/meminfo.
read_mem_pct() {
  local total available used_pct
  total="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null)"
  available="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null)"
  if [ -z "${total}" ] || [ "${total}" -le 0 ] || [ -z "${available}" ]; then
    printf '0'
    return 0
  fi
  used_pct=$(( 100 - (100 * available / total) ))
  if [ "${used_pct}" -lt 0 ]; then
    used_pct=0
  fi
  printf '%s' "${used_pct}"
}

# Returns swap usage percentage from /proc/meminfo.
read_swap_pct() {
  local total free used_pct
  total="$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo 2>/dev/null)"
  free="$(awk '/^SwapFree:/ {print $2}' /proc/meminfo 2>/dev/null)"
  if [ -z "${total}" ] || [ "${total}" -le 0 ] || [ -z "${free}" ]; then
    printf '0'
    return 0
  fi
  used_pct=$(( 100 - (100 * free / total) ))
  if [ "${used_pct}" -lt 0 ]; then
    used_pct=0
  fi
  printf '%s' "${used_pct}"
}

# Returns the highest disk usage percentage across mounted filesystems.
read_disk_pct() {
  df -P -x tmpfs -x devtmpfs 2>/dev/null | awk 'NR > 1 {gsub(/%/, "", $5); if ($5 > max) max = $5} END {print max + 0}'
}

# Returns the highest inode usage percentage across mounted filesystems.
read_inode_pct() {
  df -Pi -x tmpfs -x devtmpfs 2>/dev/null | awk 'NR > 1 {gsub(/%/, "", $5); if ($5 > max) max = $5} END {print max + 0}'
}

# Emits one INFO metrics line plus any threshold alerts.
run_health_module() {
  local cpu_pct load_per_core mem_pct swap_pct disk_pct inode_pct
  cpu_pct="$(read_cpu_pct)"
  load_per_core="$(read_load_per_core)"
  mem_pct="$(read_mem_pct)"
  swap_pct="$(read_swap_pct)"
  disk_pct="$(read_disk_pct)"
  inode_pct="$(read_inode_pct)"

  raise_alert INFO health SYS-100 "CPU ${cpu_pct}% MEM ${mem_pct}% SWAP ${swap_pct}% DISK ${disk_pct}% INODE ${inode_pct}% LOAD/core ${load_per_core}" "cpu=${cpu_pct} load_per_core=${load_per_core} mem=${mem_pct} swap=${swap_pct} disk=${disk_pct} inode=${inode_pct}"

  if [ "${cpu_pct:-0}" -ge "${CPU_PCT_WARN:-85}" ]; then
    raise_alert MEDIUM health SYS-001 "CPU usage is ${cpu_pct}%" "cpu=${cpu_pct}"
  fi

  awk -v avg="${load_per_core:-0}" -v warn="${LOAD_PER_CORE_WARN:-1.0}" 'BEGIN { exit !(avg >= warn) }'
  if [ "$?" -eq 0 ]; then
    raise_alert LOW health SYS-002 "Load per core is ${load_per_core}" "load_per_core=${load_per_core}"
  fi

  awk -v avg="${load_per_core:-0}" -v crit="${LOAD_PER_CORE_CRIT:-2.0}" 'BEGIN { exit !(avg >= crit) }'
  if [ "$?" -eq 0 ]; then
    raise_alert MEDIUM health SYS-003 "Load per core is ${load_per_core}" "load_per_core=${load_per_core}"
  fi

  if [ "${mem_pct:-0}" -ge "${MEM_PCT_WARN:-90}" ]; then
    raise_alert MEDIUM health SYS-004 "Memory usage is ${mem_pct}%" "mem=${mem_pct}"
  fi

  if [ "${swap_pct:-0}" -ge "${SWAP_PCT_WARN:-50}" ]; then
    raise_alert MEDIUM health SYS-005 "Swap usage is ${swap_pct}%" "swap=${swap_pct}"
  fi

  if [ "${disk_pct:-0}" -ge "${DISK_PCT_WARN:-85}" ]; then
    raise_alert LOW health SYS-006 "Filesystem usage is ${disk_pct}%" "disk=${disk_pct}"
  fi

  if [ "${disk_pct:-0}" -ge "${DISK_PCT_CRIT:-95}" ]; then
    raise_alert HIGH health SYS-007 "Filesystem usage is ${disk_pct}%" "disk=${disk_pct}"
  fi

  if [ "${inode_pct:-0}" -ge "${INODE_PCT_WARN:-90}" ]; then
    raise_alert HIGH health SYS-008 "Inode usage is ${inode_pct}%" "inode=${inode_pct}"
  fi
}