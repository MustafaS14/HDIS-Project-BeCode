HIDS Implementation Checklist

Summary
- I added `SPEC.md` to the repository root to keep the contract in-repo.
- This file (`HIDS.md`) maps SPEC tasks to the files to create and the exact
  verification commands you should run.

Status overview (what I changed)
- SPEC.md: placed at repository root (see file).
- HIDS.md: this checklist created.
- No detection code has been implemented yet; I refrained from modifying
  existing scripts to avoid accidental system changes.

What to verify per SPEC task

**Task 1 — lib/util.sh**
- File: lib/util.sh
- Functions required: `is_tty`, `flatten`, `json_escape`, `colourise`.
- Quick checks (run from repo root):
  - `bash -c 'source lib/util.sh || true; flatten "$(who)"'`
  - `bash -c 'source lib/util.sh || true; printf "%s\n" "$(json_escape "a\"b\\c")"'`
- Acceptance: `flatten "$(who)"` prints a single line; `json_escape 'a"b\\c'` prints `a\"b\\c`.

**Task 2 — config/hids.conf + lib/config.sh**
- File: config/hids.conf and lib/config.sh
- `load_config()` should source config if present and set defaults with `: "${VAR:=default}"`.
- Quick checks:
  - `grep -n "CPU_PCT_WARN" config/hids.conf` (file exists)
  - `bash -c 'source lib/config.sh || true; load_config || true; env | grep CPU_PCT_WARN'`

**Task 3 — lib/rules.sh**
- File: lib/rules.sh
- Requirements: associative arrays `RULE_IMPACT` and `RULE_ACTION`, and accessors `rule_impact` and `rule_action`.
- Quick checks:
  - `bash -c 'source lib/rules.sh || true; rule_impact USR-005'`

**Task 4 — lib/alert.sh**
- File: lib/alert.sh
- Functions: `init_alerting`, `suppressed`, `raise_alert`, `max_severity_exit_code`.
- Hard requirements: `raise_alert` must call `flatten` and `json_escape` on message and evidence; suppression windows based on `SUPPRESS_WINDOW_LOW`/`HIGH`; include suppressed counts; enforce `MAX_ALERTS_PER_RUN` and emit `ALR-002` when exceeded.
- Quick checks (do not run as root unless you expect logs to change):
  - `bash -c 'source lib/util.sh lib/rules.sh lib/alert.sh || true; init_alerting || true; raise_alert CRITICAL testmod FIM-999 "test message" "evidence with newline\nsecond"'`
  - Inspect `logs/hids.log` for a single JSON line. Example: `tail -n 5 logs/hids.log`.

**Task 5 — modules/health.sh**
- File: modules/health.sh
- Functions: `read_cpu_pct`, `read_load_per_core`, `read_mem_pct`, `read_swap_pct`, `run_health_module`.
- Critical fix: CPU sampling twice inside the same call.
- Quick checks:
  - `bash -c 'source lib/config.sh lib/util.sh modules/health.sh || true; load_config || true; read_cpu_pct || true; read_load_per_core || true'`
  - `bash -c 'source modules/health.sh || true; run_health_module || true'` then check `logs/hids.log` for SYS-100.

**Task 6 — modules/users.sh (cut-down verification)**
- Files: modules/users.sh, baseline/users.txt, baseline/groups.txt
- Functions to check: `read_failed_logins`, `check_new_accounts`, `check_group_changes`, `check_lastlog`, `check_account_file_permissions`, `run_users_module`.
- Quick checks:
  - `bash -c 'source modules/users.sh || true; run_users_module || true'` then `tail -n 20 logs/hids.log`.

**Task 7 — modules/procnet.sh (cut-down verification)**
- Files: modules/procnet.sh, baseline/listeners.txt
- Key functions: `enumerate_processes`, `check_process_paths`, `check_hidden_processes`, `read_listeners`, `run_procnet_module`.
- Quick checks:
  - `bash -c 'source modules/procnet.sh || true; run_procnet_module || true'`

**Task 8 — modules/fim.sh (cut-down verification)**
- Files: modules/fim.sh, baseline/fim.txt
- Key functions: `fingerprint_file`, `write_fim_baseline`, `check_fim`, `check_suid_inventory`, `run_fim_module`.
- Quick checks:
  - `bash -c 'source modules/fim.sh || true; run_fim_module || true'` (without `--full` by default)

**Task 9 — hids.sh orchestrator**
- File: hids.sh (top-level)
- Requirements: CLI flags, source `lib/*.sh` and `modules/*.sh`, dispatch, exit with `max_severity_exit_code`.
- Quick checks:
  - `bash hids.sh --help`
  - `bash hids.sh --once` then `echo $?` should return an exit code as per severities.

**Task 10 — modules/report.sh**
- File: modules/report.sh
- Requirements: generate `logs/hids-summary.txt` and print short human report with `rule_impact` & `rule_action`.
- Quick checks:
  - `bash -c 'source modules/report.sh || true; run_report || true'` (function name may differ; check file)

**Task 11 — simulate_attack.sh**
- File: simulate_attack.sh
- Requirements: destructive operations gated behind `HIDS_SIMULATE_OK=1`, `--cleanup` to revert, scoring of expected rules.
- Quick checks:
  - Inspect file, ensure it refuses to run unless `HIDS_SIMULATE_OK=1` is set.

**Task 12 — README.md**
- File: README.md
- Requirements: document what it does, install, CLI flags, log format, full rule table, how to change thresholds, port whitelist, ELK setup, exit codes.
- Quick checks:
  - Open README.md and verify the required sections are present.

General verification notes
- Log format: each `raise_alert` must append one JSON object per line to `logs/hids.log`.
  Verify with: `tail -n 5 logs/hids.log` — each line must parse as JSON.
- All functions must have a one-line `#` comment above them.
  Use `grep -n "^function\|() {" -n` or visually inspect files under `lib/` and `modules/`.
- Shell options: each script must begin with `#!/usr/bin/env bash` and `set -uo pipefail`.

What I did not change (you must verify or ask me to implement)
- No detection modules were implemented yet; the SPEC was added and a checklist created.
- I did not modify existing scripts like `elk_ship.sh` or `send_email_report.sh`.

Next steps (I can take these if you want)
- Implement `lib/util.sh` and `lib/alert.sh` (high priority).
- Implement `modules/health.sh` and basic `hids.sh` CLI to enable `--once` runs.

If you want me to proceed, tell me which Task to implement first (recommended: Task 1 `lib/util.sh`).


Repository files I created/modified
- [SPEC.md](SPEC.md)
- [HIDS.md](HIDS.md)


Where to look in the repo now
- SPEC text: [SPEC.md](SPEC.md)
- Checklist: [HIDS.md](HIDS.md)


