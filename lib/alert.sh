#!/usr/bin/env bash
set -uo pipefail

if [ -f "${BASH_SOURCE%/*}/util.sh" ]; then
  source "${BASH_SOURCE%/*}/util.sh"
fi

if [ -f "${BASH_SOURCE%/*}/rules.sh" ]; then
  source "${BASH_SOURCE%/*}/rules.sh"
fi

HIDS_ROOT="${HIDS_ROOT:-$(cd "${BASH_SOURCE%/*}/.." && pwd)}"
HIDS_LOG_DIR="${HIDS_LOG_DIR:-${HIDS_ROOT}/logs}"
HIDS_BASELINE_DIR="${HIDS_BASELINE_DIR:-${HIDS_ROOT}/baseline}"
HIDS_STATE_DIR="${HIDS_STATE_DIR:-${HIDS_ROOT}/state}"
HIDS_LOG_FILE="${HIDS_LOG_FILE:-${HIDS_LOG_DIR}/hids.log}"
HIDS_SUPPRESS_DB="${HIDS_SUPPRESS_DB:-${HIDS_STATE_DIR}/suppress.db}"

HIDS_RUN_ALERTS=0
HIDS_MAX_SEVERITY=0
HIDS_SUPPRESSED_NONCRITICAL=0
HIDS_SUPPRESS_OPEN=0

# Returns the current UTC timestamp in ISO-8601 format.
utc_timestamp() {
  printf '%(%Y-%m-%dT%H:%M:%SZ)T' -1
}

# Returns a numeric rank for a severity label.
severity_rank() {
  case "${1:-}" in
    INFO) printf '%s' 0 ;;
    LOW) printf '%s' 1 ;;
    MEDIUM) printf '%s' 2 ;;
    HIGH) printf '%s' 3 ;;
    CRITICAL) printf '%s' 4 ;;
    *) printf '%s' 0 ;;
  esac
}

# Returns the named severity for a numeric rank.
severity_name() {
  case "${1:-0}" in
    0) printf '%s' INFO ;;
    1) printf '%s' LOW ;;
    2) printf '%s' MEDIUM ;;
    3) printf '%s' HIGH ;;
    4) printf '%s' CRITICAL ;;
    *) printf '%s' INFO ;;
  esac
}

# Initialises log/baseline/state directories and the alert counter.
init_alerting() {
  mkdir -p "${HIDS_LOG_DIR}" "${HIDS_BASELINE_DIR}" "${HIDS_STATE_DIR}"
  : > "${HIDS_LOG_FILE}"
  : > "${HIDS_SUPPRESS_DB}"
  HIDS_RUN_ALERTS=0
  HIDS_MAX_SEVERITY=0
  HIDS_SUPPRESSED_NONCRITICAL=0
  HIDS_SUPPRESS_OPEN=0
}

# Returns 0 if this rule+evidence fired within its suppression window.
suppressed() {
  local rule_id="${1:-}"
  local evidence="${2:-}"
  local severity="${3:-INFO}"
  local window=0

  case "${severity}" in
    INFO|LOW) window="${SUPPRESS_WINDOW_LOW:-3600}" ;;
    MEDIUM|HIGH) window="${SUPPRESS_WINDOW_HIGH:-900}" ;;
    CRITICAL) return 1 ;;
    *) window="${SUPPRESS_WINDOW_HIGH:-900}" ;;
  esac

  local key
  key="$(flatten "${rule_id}|${evidence}")"

  local now
  now="$(printf '%(%s)T' -1)"

  local line prev_epoch prev_count prev_key
  if [ -f "${HIDS_SUPPRESS_DB}" ]; then
    while IFS=$'\t' read -r prev_key prev_epoch prev_count; do
      [ -z "${prev_key:-}" ] && continue
      if [ "${prev_key}" = "${key}" ]; then
        if [ $(( now - prev_epoch )) -lt "${window}" ]; then
          local new_count=$(( prev_count + 1 ))
          : > "${HIDS_SUPPRESS_DB}.tmp"
          while IFS=$'\t' read -r line_key line_epoch line_count; do
            [ -z "${line_key:-}" ] && continue
            if [ "${line_key}" = "${key}" ]; then
              printf '%s\t%s\t%s\n' "${key}" "${prev_epoch}" "${new_count}" >> "${HIDS_SUPPRESS_DB}.tmp"
            else
              printf '%s\t%s\t%s\n' "${line_key}" "${line_epoch}" "${line_count}" >> "${HIDS_SUPPRESS_DB}.tmp"
            fi
          done < "${HIDS_SUPPRESS_DB}"
          mv "${HIDS_SUPPRESS_DB}.tmp" "${HIDS_SUPPRESS_DB}"
          HIDS_SUPPRESSED_NONCRITICAL=$(( HIDS_SUPPRESSED_NONCRITICAL + 1 ))
          return 0
        fi
        return 1
      fi
    done < "${HIDS_SUPPRESS_DB}"
  fi

  : > "${HIDS_SUPPRESS_DB}.tmp"
  if [ -f "${HIDS_SUPPRESS_DB}" ]; then
    cat "${HIDS_SUPPRESS_DB}" >> "${HIDS_SUPPRESS_DB}.tmp"
  fi
  printf '%s\t%s\t%s\n' "${key}" "${now}" 1 >> "${HIDS_SUPPRESS_DB}.tmp"
  mv "${HIDS_SUPPRESS_DB}.tmp" "${HIDS_SUPPRESS_DB}"
  return 1
}

# Returns the highest severity seen this run as an exit code: 0 clean, 1 low/medium, 2 high, 3 critical.
max_severity_exit_code() {
  case "$(severity_name "${HIDS_MAX_SEVERITY}")" in
    INFO) return 0 ;;
    LOW|MEDIUM) return 1 ;;
    HIGH) return 2 ;;
    CRITICAL) return 3 ;;
    *) return 0 ;;
  esac
}

# Escapes a string for JSON output after flattening newlines and tabs.
escape_json_field() {
  flatten "${1:-}" | json_escape
}

# Emits one alert, updates state, and logs a JSON line plus terminal output.
raise_alert() {
  local sev="${1:-INFO}"
  local module="${2:-general}"
  local rule_id="${3:-ALR-000}"
  local msg="${4:-}"
  local evidence="${5:-}"

  local sev_rank
  sev_rank="$(severity_rank "${sev}")"

  if [ "${rule_id}" != "ALR-002" ] && [ "${HIDS_RUN_ALERTS}" -ge "${MAX_ALERTS_PER_RUN:-50}" ] && [ "${sev}" != "CRITICAL" ]; then
    HIDS_SUPPRESSED_NONCRITICAL=$(( HIDS_SUPPRESSED_NONCRITICAL + 1 ))
    if [ "${HIDS_SUPPRESS_OPEN}" -eq 0 ]; then
      HIDS_SUPPRESS_OPEN=1
      raise_alert HIGH alert ALR-002 "Maximum alert volume exceeded; suppressing further non-critical alerts." "max_alerts=${MAX_ALERTS_PER_RUN:-50}"
    fi
    return 0
  fi

  if [ "${rule_id}" != "SYS-100" ] && [ "${sev}" != "CRITICAL" ] && suppressed "${rule_id}" "${evidence}" "${sev}"; then
    return 0
  fi

  local repeated_suffix=""
  local key
  key="$(flatten "${rule_id}|${evidence}")"
  if [ -f "${HIDS_SUPPRESS_DB}" ]; then
    while IFS=$'\t' read -r stored_key stored_epoch stored_count; do
      [ -z "${stored_key:-}" ] && continue
      if [ "${stored_key}" = "${key}" ] && [ "${stored_count:-0}" -gt 1 ]; then
        local since
        since="$(printf '%(%H:%M)T' "${stored_epoch:-0}")"
        repeated_suffix=" (repeated ${stored_count} times since ${since})"
        break
      fi
    done < "${HIDS_SUPPRESS_DB}"
  fi

  local impact action host timestamp flat_msg flat_evidence json_msg json_evidence json_impact json_action
  host="$(hostname 2>/dev/null || printf '%s' unknown)"
  timestamp="$(utc_timestamp)"
  flat_msg="$(flatten "${msg}${repeated_suffix}")"
  flat_evidence="$(flatten "${evidence}")"
  json_msg="$(json_escape "${flat_msg}")"
  json_evidence="$(json_escape "${flat_evidence}")"
  impact="$(rule_impact "${rule_id}" 2>/dev/null || printf '%s' "A security-relevant event occurred.")"
  action="$(rule_action "${rule_id}" 2>/dev/null || printf '%s' "Review the event and apply local incident response procedures.")"
  json_impact="$(json_escape "$(flatten "${impact}")")"
  json_action="$(json_escape "$(flatten "${action}")")"

  mkdir -p "${HIDS_LOG_DIR}" "${HIDS_STATE_DIR}"
  printf '{"timestamp":"%s","rule":"%s","severity":"%s","module":"%s","host":"%s","message":"%s","evidence":"%s","impact":"%s","action":"%s"}\n' \
    "${timestamp}" "${rule_id}" "${sev}" "${module}" "${host}" "${json_msg}" "${json_evidence}" "${json_impact}" "${json_action}" >> "${HIDS_LOG_FILE}"

  colourise "${sev}" "[${sev}] [${module}] [${rule_id}] ${flat_msg}"

  HIDS_RUN_ALERTS=$(( HIDS_RUN_ALERTS + 1 ))
  if [ "${sev_rank}" -gt "${HIDS_MAX_SEVERITY}" ]; then
    HIDS_MAX_SEVERITY="${sev_rank}"
  fi
}
