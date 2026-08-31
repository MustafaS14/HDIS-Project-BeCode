#!/usr/bin/env bash
set -uo pipefail

# Loads hids.conf when present and applies default values for missing variables.
load_config() {
  local config_file="${HIDS_CONFIG_FILE:-${BASH_SOURCE%/*}/../config/hids.conf}"

  if [ -f "${config_file}" ]; then
    # shellcheck disable=SC1090
    source "${config_file}"
  fi

  : "${CPU_PCT_WARN:=85}"
  : "${LOAD_PER_CORE_WARN:=1.0}"
  : "${LOAD_PER_CORE_CRIT:=2.0}"
  : "${MEM_PCT_WARN:=90}"
  : "${SWAP_PCT_WARN:=50}"
  : "${DISK_PCT_WARN:=85}"
  : "${DISK_PCT_CRIT:=95}"
  : "${INODE_PCT_WARN:=90}"

  : "${FAILED_LOGIN_WARN:=5}"
  : "${FAILED_LOGIN_CRIT:=20}"
  : "${FAILED_LOGIN_WINDOW_MIN:=10}"
  : "${PRIVILEGED_GROUPS:=sudo wheel adm docker}"

  : "${ALLOWED_LISTEN_PORTS:=22 80 443 53 631}"
  : "${SUSPICIOUS_BINARIES:=nc ncat socat nmap masscan}"
  : "${WRITABLE_EXEC_DIRS:=/tmp /var/tmp /dev/shm /run/shm}"

  : "${FIM_TIER1:=/etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/ssh/sshd_config /root/.ssh/authorized_keys}"
  : "${FIM_TIER2:=/etc/crontab /etc/hosts /etc/resolv.conf /etc/rc.local /etc/ld.so.preload}"
  : "${FIM_TIER2_DIRS:=/etc/cron.d /etc/sudoers.d /etc/systemd/system}"

  : "${SUPPRESS_WINDOW_LOW:=3600}"
  : "${SUPPRESS_WINDOW_HIGH:=900}"
  : "${MAX_ALERTS_PER_RUN:=50}"
}