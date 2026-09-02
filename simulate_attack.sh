#!/usr/bin/env bash
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${PROJECT_ROOT}/state"
SIM_STATE_FILE="${STATE_DIR}/simulate.state"
SIM_START_LINE=0

# Refuses to run unless the explicit simulation gate is enabled.
require_sim_gate() {
  if [ "${HIDS_SIMULATE_OK:-}" != "1" ]; then
    printf 'Refusing to run. Set HIDS_SIMULATE_OK=1 to enable the simulation.\n'
    exit 1
  fi
}

# Records a state entry for later cleanup.
record_state() {
  local kind="${1:-}"
  local value="${2:-}"
  mkdir -p "${STATE_DIR}"
  printf '%s\t%s\n' "${kind}" "${value}" >> "${SIM_STATE_FILE}"
}

# Runs a command and records the result when it succeeds.
run_and_record() {
  local kind="${1:-}"
  shift || true
  if "$@"; then
    record_state "${kind}" "$*"
    return 0
  fi
  return 1
}

# Applies the demonstration steps used to exercise the detectors.
run_attack_steps() {
  mkdir -p "${STATE_DIR}"
  SIM_START_LINE="$(awk 'END {print NR+0}' "${PROJECT_ROOT}/logs/hids.log" 2>/dev/null || printf '0')"
  : > "${SIM_STATE_FILE}"

  if command -v useradd >/dev/null 2>&1; then
    run_and_record "command" useradd -o -u 0 svc-backup || true
  fi

  if [ -r /bin/bash ] && [ -w /tmp ]; then
    cp /bin/bash /tmp/.x 2>/dev/null || true
    chmod 4755 /tmp/.x 2>/dev/null || true
    record_state "file" "/tmp/.x"
  fi

  if [ -x /tmp/.x ]; then
    /tmp/.x -c 'sleep 300' >/dev/null 2>&1 &
    record_state "pid" "$!"
  fi

  if command -v nc >/dev/null 2>&1; then
    nc -lnp 8888 >/dev/null 2>&1 &
    record_state "pid" "$!"
  fi

  if [ -w /etc/cron.d ] 2>/dev/null; then
    printf '* * * * * root /tmp/.x\n' > /etc/cron.d/x 2>/dev/null || true
    record_state "file" "/etc/cron.d/x"
  fi

  if [ -w /root/.ssh ] 2>/dev/null; then
    printf '\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample attacker@host\n' >> /root/.ssh/authorized_keys 2>/dev/null || true
    record_state "file" "/root/.ssh/authorized_keys"
  fi

  if [ -n "${HOME:-}" ] && [ -w "${HOME}" ]; then
    : > "${HOME}/.bash_history" 2>/dev/null || true
    record_state "file" "${HOME}/.bash_history"
  fi

  if [ -w /etc ] 2>/dev/null; then
    : > /etc/ld.so.preload 2>/dev/null || true
    record_state "file" "/etc/ld.so.preload"
  fi
}

# Greps logs/hids.log for each expected rule ID emitted after the run start.
score_detection() {
  local log_file="${PROJECT_ROOT}/logs/hids.log"
  local tail_file="${STATE_DIR}/simulate.tail"
  local total=0 matched=0 missed=0 line
  local expected_rules=(
    "USR-005"
    "FIM-006"
    "FIM-007"
    "PRC-001"
    "NET-001"
    "NET-002"
    "FIM-010"
    "USR-009"
    "USR-012"
    "FIM-008"
  )

  awk -v start="${SIM_START_LINE}" 'NR > start' "${log_file}" > "${tail_file}" 2>/dev/null || :

  printf 'Step | Rule | Result\n'
  printf '%s\n' '-----|------|-------'
  for line in "${expected_rules[@]}"; do
    total=$(( total + 1 ))
    if grep -Fq "\"rule\":\"${line}\"" "${tail_file}"; then
      matched=$(( matched + 1 ))
      printf 'PASS | %s | seen\n' "${line}"
    else
      missed=$(( missed + 1 ))
      printf 'MISS | %s | not seen\n' "${line}"
    fi
  done

  printf 'Detected %s/%s rules (%s%%)  -- missed: ' "${matched}" "${total}" "$(( 100 * matched / total ))"
  if [ "${missed}" -eq 0 ]; then
    printf 'none\n'
  else
    local first_missing=""
    for line in "${expected_rules[@]}"; do
      if ! grep -Fq "\"rule\":\"${line}\"" "${tail_file}"; then
        first_missing="${line}"
        break
      fi
    done
    printf '%s\n' "${first_missing}"
  fi
}

# Reverses the changes recorded during the simulation run.
cleanup_simulation() {
  [ -f "${SIM_STATE_FILE}" ] || return 0
  while IFS=$'\t' read -r kind value; do
    [ -z "${kind:-}" ] && continue
    case "${kind}" in
      file)
        rm -f "${value}" 2>/dev/null || true
        ;;
      pid)
        kill "${value}" 2>/dev/null || true
        ;;
    esac
  done < "${SIM_STATE_FILE}"
}

# Runs the simulation, scores the detections, and optionally cleans up.
main() {
  local mode="${1:---run}"
  require_sim_gate
  case "${mode}" in
    --cleanup)
      cleanup_simulation
      ;;
    --run|*)
      run_attack_steps
      bash "${PROJECT_ROOT}/HIDS.sh" --once >/dev/null 2>&1 || true
      score_detection
      ;;
  esac
}

main "$@"
