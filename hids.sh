#!/usr/bin/env bash
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Sources all shared libraries and modules used by the orchestrator.
load_hids_stack() {
  source "${PROJECT_ROOT}/lib/util.sh"
  source "${PROJECT_ROOT}/lib/config.sh"
  source "${PROJECT_ROOT}/lib/rules.sh"
  source "${PROJECT_ROOT}/lib/alert.sh"
  source "${PROJECT_ROOT}/modules/health.sh"
  source "${PROJECT_ROOT}/modules/users.sh"
  source "${PROJECT_ROOT}/modules/procnet.sh"
  source "${PROJECT_ROOT}/modules/fim.sh"
  source "${PROJECT_ROOT}/modules/report.sh"
}

# Runs the fast checks used by cron and report/email/ELK flows.
run_once_checks() {
  init_alerting
  run_health_module
  run_users_module
  run_procnet_module
  run_fim_module
}

# Runs the full checks including the expensive FIM sweep.
run_full_checks() {
  init_alerting
  run_health_module
  run_users_module
  run_procnet_module
  run_fim_module --full
}

# Writes the configured baselines without emitting alerts.
run_baseline_mode() {
  export HIDS_SUPPRESS_BASELINE_ALERTS=1
  init_alerting
  write_users_baseline
  ensure_listener_baseline
  write_fim_baseline
}

# Installs both cron schedules for the fast and full runs.
install_cron_jobs() {
  local script_path cron_file existing_cron
  script_path="${PROJECT_ROOT}/hids.sh"
  cron_file="/tmp/hids.cron.$$"
  existing_cron=""
  if crontab -l >/dev/null 2>&1; then
    existing_cron="$(crontab -l 2>/dev/null || true)"
  fi
  {
    printf '%s\n' "${existing_cron}"
    printf '*/15 * * * * %s --once >/dev/null 2>&1\n' "${script_path}"
    printf '0 * * * * %s --full >/dev/null 2>&1\n' "${script_path}"
  } | awk 'NF > 0' > "${cron_file}"
  crontab "${cron_file}"
}

# Prints the supported command-line flags.
print_help() {
  cat <<'USAGE'
Usage: hids.sh [--baseline|--once|--full|--report|--email-report|--ship-elk|--simulate|--install-cron|--help]
USAGE
}

# Dispatches the selected command-line flag.
main() {
  local mode="${1:---help}"
  load_hids_stack
  load_config

  case "${mode}" in
    --baseline)
      run_baseline_mode
      ;;
    --once)
      run_once_checks
      max_severity_exit_code
      return $?
      ;;
    --full)
      run_full_checks
      max_severity_exit_code
      return $?
      ;;
    --report)
      run_once_checks
      generate_report
      max_severity_exit_code
      return $?
      ;;
    --email-report)
      run_once_checks
      if [ -x "${PROJECT_ROOT}/send_email_report.sh" ]; then
        "${PROJECT_ROOT}/send_email_report.sh"
      fi
      max_severity_exit_code
      return $?
      ;;
    --ship-elk)
      run_once_checks
      if [ -x "${PROJECT_ROOT}/elk/elk_ship.sh" ]; then
        "${PROJECT_ROOT}/elk/elk_ship.sh" --once
      fi
      max_severity_exit_code
      return $?
      ;;
    --simulate)
      if [ -x "${PROJECT_ROOT}/simulate_attack.sh" ]; then
        "${PROJECT_ROOT}/simulate_attack.sh"
      else
        printf 'simulate_attack.sh is not available yet.\n'
        return 1
      fi
      ;;
    --install-cron)
      install_cron_jobs
      ;;
    --help|-h|*)
      print_help
      ;;
  esac
}

main "$@"
