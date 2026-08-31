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

# Emits "path<TAB>mode<TAB>uid<TAB>gid<TAB>size<TAB>sha256" for one file.
fingerprint_file() {
  local file_path="${1:-}"
  local size mode uid gid digest
  [ -n "${file_path}" ] || return 0
  [ -e "${file_path}" ] || return 0
  mode="$(stat -c '%a' "${file_path}" 2>/dev/null || true)"
  uid="$(stat -c '%u' "${file_path}" 2>/dev/null || true)"
  gid="$(stat -c '%g' "${file_path}" 2>/dev/null || true)"
  size="$(stat -c '%s' "${file_path}" 2>/dev/null || true)"
  [ -n "${mode}" ] || return 0
  digest="$(sha256sum "${file_path}" 2>/dev/null | awk '{print $1}')"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "${file_path}" "${mode}" "${uid}" "${gid}" "${size}" "${digest}"
}

# Collects the monitored files and their tiers into a baseline-ready stream.
collect_fim_targets() {
  local target
  for target in ${FIM_TIER1:-}; do
    [ -e "${target}" ] && fingerprint_file "${target}" | awk -v tier="T1" '{print tier "\t" $0}'
  done

  for target in ${FIM_TIER2:-}; do
    [ -e "${target}" ] && fingerprint_file "${target}" | awk -v tier="T2" '{print tier "\t" $0}'
  done

  local monitored_dir found_path
  for monitored_dir in ${FIM_TIER2_DIRS:-}; do
    [ -d "${monitored_dir}" ] || continue
    while IFS= read -r found_path; do
      [ -n "${found_path}" ] || continue
      fingerprint_file "${found_path}" | awk -v tier="T2" '{print tier "\t" $0}'
    done < <(find "${monitored_dir}" -type f 2>/dev/null)
  done
}

# Writes baseline/fim.txt from FIM_TIER1 + FIM_TIER2 + FIM_TIER2_DIRS contents.
write_fim_baseline() {
  mkdir -p "${BASELINE_DIR}"
  if [ ! -f "${BASELINE_DIR}/fim.txt" ] && [ -z "${HIDS_SUPPRESS_BASELINE_ALERTS:-}" ]; then
    raise_alert MEDIUM fim FIM-014 "No file-integrity baseline existed; recorded an unverified state" "baseline=${BASELINE_DIR}/fim.txt"
  fi
  : > "${BASELINE_DIR}/fim.txt"
  collect_fim_targets > "${BASELINE_DIR}/fim.txt"
}

# Loads a baseline file into associative arrays keyed by path.
load_fim_snapshot() {
  local snapshot_file="${1:-}"
  local prefix="${2:-base}"
  local tier path mode uid gid size digest
  declare -n out_tier="${prefix}_tier"
  declare -n out_mode="${prefix}_mode"
  declare -n out_uid="${prefix}_uid"
  declare -n out_gid="${prefix}_gid"
  declare -n out_size="${prefix}_size"
  declare -n out_digest="${prefix}_digest"

  while IFS=$'\t' read -r tier path mode uid gid size digest; do
    [ -n "${path:-}" ] || continue
    out_tier["${path}"]="${tier}"
    out_mode["${path}"]="${mode}"
    out_uid["${path}"]="${uid}"
    out_gid["${path}"]="${gid}"
    out_size["${path}"]="${size}"
    out_digest["${path}"]="${digest}"
  done < "${snapshot_file}"
}

# Compares current fingerprints to baseline, reporting WHAT changed.
check_fim() {
  local baseline_file="${BASELINE_DIR}/fim.txt"
  if [ ! -f "${baseline_file}" ]; then
    write_fim_baseline
    return 0
  fi

  declare -A base_tier base_mode base_uid base_gid base_size base_digest
  declare -A cur_tier cur_mode cur_uid cur_gid cur_size cur_digest

  load_fim_snapshot "${baseline_file}" base

  local current_file
  current_file="${BASELINE_DIR}/fim.current.$$"
  : > "${current_file}"
  collect_fim_targets > "${current_file}"
  load_fim_snapshot "${current_file}" cur

  local path
  for path in "${!base_digest[@]}"; do
    if [ -z "${cur_digest[${path}]:-}" ]; then
      if [ "${base_tier[${path}]:-}" = "T1" ]; then
        raise_alert CRITICAL fim FIM-002 "Tier 1 file '${path}' is missing" "path=${path}"
      fi
      continue
    fi

    if [ "${base_digest[${path}]}" != "${cur_digest[${path}]}" ]; then
      if [ "${base_tier[${path}]:-}" = "T1" ]; then
        raise_alert CRITICAL fim FIM-001 "sha256 ${base_digest[${path}]} -> ${cur_digest[${path}]} on ${path}" "path=${path} old_sha256=${base_digest[${path}]} new_sha256=${cur_digest[${path}]}"
      else
        if [ "${path}" = "/etc/crontab" ] || printf '%s' "${path}" | grep -Eq '^/etc/cron\.d/'; then
          raise_alert HIGH fim FIM-010 "Changed cron file '${path}'" "path=${path} old_sha256=${base_digest[${path}]} new_sha256=${cur_digest[${path}]}"
        else
          raise_alert HIGH fim FIM-003 "sha256 ${base_digest[${path}]} -> ${cur_digest[${path}]} on ${path}" "path=${path} old_sha256=${base_digest[${path}]} new_sha256=${cur_digest[${path}]}"
        fi
      fi
    fi

    if [ "${base_mode[${path}]}" != "${cur_mode[${path}]}" ]; then
      raise_alert HIGH fim FIM-004 "mode ${base_mode[${path}]} -> ${cur_mode[${path}]} on ${path}" "path=${path} old_mode=${base_mode[${path}]} new_mode=${cur_mode[${path}]}"
    fi

    if [ "${base_uid[${path}]}" != "${cur_uid[${path}]}" ] || [ "${base_gid[${path}]}" != "${cur_gid[${path}]}" ]; then
      raise_alert HIGH fim FIM-005 "owner/group ${base_uid[${path}]}:${base_gid[${path}]} -> ${cur_uid[${path}]}:${cur_gid[${path}]} on ${path}" "path=${path} old_owner=${base_uid[${path}]}:${base_gid[${path}]} new_owner=${cur_uid[${path}]}:${cur_gid[${path}]}"
    fi

    case "${path}" in
      *.log|*/log/*)
        if [ "${cur_size[${path}]}" -lt "${base_size[${path}]}" ]; then
          raise_alert HIGH fim FIM-012 "size ${base_size[${path}]} -> ${cur_size[${path}]} on ${path}" "path=${path} old_size=${base_size[${path}]} new_size=${cur_size[${path}]}"
        fi
        ;;
    esac
  done

  for path in "${!cur_digest[@]}"; do
    if [ -z "${base_digest[${path}]:-}" ]; then
      if [ "${path}" = "/etc/crontab" ] || printf '%s' "${path}" | grep -Eq '^/etc/cron\.d/'; then
        raise_alert HIGH fim FIM-010 "New cron file '${path}' appeared" "path=${path} sha256=${cur_digest[${path}]}"
      else
        raise_alert HIGH fim FIM-003 "New monitored file '${path}' appeared" "path=${path} sha256=${cur_digest[${path}]}"
      fi
    fi
  done

  rm -f "${current_file}" 2>/dev/null || true

  if [ -f /etc/ld.so.preload ]; then
    raise_alert CRITICAL fim FIM-008 "/etc/ld.so.preload exists" "path=/etc/ld.so.preload"
  fi
}

# Diffs SUID/SGID inventory. Runs only when --full is passed.
check_suid_inventory() {
  local baseline_file="${BASELINE_DIR}/suid.txt" current_file path mode uid gid key
  mkdir -p "${BASELINE_DIR}"
  if [ ! -f "${baseline_file}" ]; then
    : > "${baseline_file}"
  fi

  current_file="${BASELINE_DIR}/suid.current.$$"
  : > "${current_file}"
  while IFS= read -r path; do
    [ -n "${path}" ] || continue
    mode="$(stat -c '%a' "${path}" 2>/dev/null || true)"
    uid="$(stat -c '%u' "${path}" 2>/dev/null || true)"
    gid="$(stat -c '%g' "${path}" 2>/dev/null || true)"
    printf '%s\t%s\t%s\t%s\n' "${path}" "${mode}" "${uid}" "${gid}" >> "${current_file}"
  done < <(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)

  while IFS=$'\t' read -r path mode uid gid; do
    [ -n "${path:-}" ] || continue
    if ! grep -Fq "${path}" "${baseline_file}" 2>/dev/null; then
      raise_alert CRITICAL fim FIM-006 "New SUID/SGID binary '${path}'" "path=${path} mode=${mode} uid=${uid} gid=${gid}"
      case "${path}" in
        /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*) : ;;
        *) raise_alert CRITICAL fim FIM-007 "SUID/SGID binary outside trusted directories: ${path}" "path=${path} mode=${mode} uid=${uid} gid=${gid}" ;;
      esac
    fi
  done < "${current_file}"

  rm -f "${current_file}" 2>/dev/null || true
}

# Orchestrates. Accepts optional "--full" for expensive filesystem sweeps.
run_fim_module() {
  local mode="${1:---fast}"
  mkdir -p "${BASELINE_DIR}"
  if [ ! -f "${BASELINE_DIR}/fim.txt" ]; then
    write_fim_baseline
    return 0
  fi

  check_fim
  if [ "${mode}" = "--full" ]; then
    check_suid_inventory
  fi
}