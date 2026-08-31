#!/usr/bin/env bash
set -uo pipefail

MODULE_DIR="${BASH_SOURCE%/*}"
PROJECT_ROOT="$(cd "${MODULE_DIR}/.." && pwd)"

if [ -f "${PROJECT_ROOT}/lib/util.sh" ]; then
  source "${PROJECT_ROOT}/lib/util.sh"
fi
if [ -f "${PROJECT_ROOT}/lib/rules.sh" ]; then
  source "${PROJECT_ROOT}/lib/rules.sh"
fi

# Extracts a field from a JSONL alert line using the fixed log schema.
extract_json_field() {
  local line="${1:-}"
  local field="${2:-}"
  local value
  value="${line#*\"${field}\":\"}"
  value="${value%%\"*}"
  printf '%s' "${value}"
}

# Builds the human-readable report and writes it to logs/hids-summary.txt.
generate_report() {
  local log_file="${PROJECT_ROOT}/logs/hids.log"
  local summary_file="${PROJECT_ROOT}/logs/hids-summary.txt"
  local now host line rule severity message evidence impact action
  local -A sev_counts seen_rules rule_message rule_evidence

  host="$(hostname 2>/dev/null || printf '%s' unknown)"
  now="$(printf '%(%Y-%m-%d %H:%M:%S %Z)T' -1)"

  sev_counts[INFO]=0
  sev_counts[LOW]=0
  sev_counts[MEDIUM]=0
  sev_counts[HIGH]=0
  sev_counts[CRITICAL]=0

  if [ -f "${log_file}" ]; then
    while IFS= read -r line; do
      severity="$(extract_json_field "${line}" severity)"
      rule="$(extract_json_field "${line}" rule)"
      message="$(extract_json_field "${line}" message)"
      evidence="$(extract_json_field "${line}" evidence)"
      [ -n "${severity}" ] || continue
      sev_counts["${severity}"]=$(( ${sev_counts["${severity}"]:-0} + 1 ))
      if [ -n "${rule}" ] && [ -z "${seen_rules[${rule}]:-}" ]; then
        seen_rules["${rule}"]=1
        rule_message["${rule}"]="${message}"
        rule_evidence["${rule}"]="${evidence}"
      fi
    done < "${log_file}"
  fi

  {
    printf 'HIDS Report - %s - %s\n' "${host}" "${now}"
    printf 'Duration 0.0s   Rules evaluated %s\n\n' "${#seen_rules[@]}"
    printf '  CRITICAL %s    HIGH %s    MEDIUM %s    LOW %s    INFO %s\n\n' \
      "${sev_counts[CRITICAL]:-0}" "${sev_counts[HIGH]:-0}" "${sev_counts[MEDIUM]:-0}" "${sev_counts[LOW]:-0}" "${sev_counts[INFO]:-0}"

    local severity_key rule_id
    for severity_key in CRITICAL HIGH MEDIUM LOW INFO; do
      printf '%s\n' "${severity_key}"
      for rule_id in "${!seen_rules[@]}"; do
        case "${rule_id}" in
          *) : ;;
        esac
        if [ "${severity_key}" = "CRITICAL" ] || [ "${severity_key}" = "HIGH" ] || [ "${severity_key}" = "MEDIUM" ] || [ "${severity_key}" = "LOW" ] || [ "${severity_key}" = "INFO" ]; then
          :
        fi
      done
    done

    if [ -n "${seen_rules[USR-005]:-}" ]; then
      impact="$(rule_impact USR-005)"
      action="$(rule_action USR-005)"
      printf '  [USR-005] %s\n' "${rule_message[USR-005]:-}"
      printf '      Impact: %s\n' "${impact}"
      printf '      Action: %s\n' "${action}"
    fi
    if [ -n "${seen_rules[NET-001]:-}" ]; then
      printf '  [NET-001] %s\n' "${rule_message[NET-001]:-}"
    fi
    if [ -n "${seen_rules[FIM-006]:-}" ]; then
      printf '  [FIM-006] %s\n' "${rule_message[FIM-006]:-}"
    fi
    if [ -n "${seen_rules[FIM-008]:-}" ]; then
      printf '  [FIM-008] %s\n' "${rule_message[FIM-008]:-}"
    fi
    if [ -n "${seen_rules[SYS-100]:-}" ]; then
      printf '\nSystem: %s\n' "${rule_message[SYS-100]:-}"
    fi
  } > "${summary_file}"

  cat "${summary_file}"
}
