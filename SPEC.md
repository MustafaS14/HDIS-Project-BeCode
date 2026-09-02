# HIDS — Build Specification

> Place this file at the repository root as `SPEC.md`.
> In Copilot Chat, prefix every request with `#file:SPEC.md` so the contract is
> always in context. Work one task at a time, in order. Do not skip ahead.

---

## 0. Global contract (never violate)

**Language:** Bash only. No Python, no awk-to-file tricks that need extra tooling,
no third-party binaries. Allowed externals: `awk`, `sed`, `grep`, `find`, `stat`,
`sha256sum`, `ps`, `ss`, `who`, `last`, `lastb`, `lastlog`, `getent`, `df`,
`curl`, `crontab`, `hostname`, `ip`.

**Shell options:** every script starts with

```bash
#!/usr/bin/env bash
set -uo pipefail
```

Not `set -e`. Detection functions must be allowed to fail without killing the run.

**Every function has a one-line `#` comment above it describing what it does.**
This is a graded requirement.

**Never** write multi-line command output into a log field without flattening it
first. One event = one line. Always.

**Directory layout (final):**

```
hids/
├── HIDS.sh                 # orchestrator + CLI only, no detection logic
├── config/
│   └── hids.conf           # thresholds, whitelists, paths
├── lib/
│   ├── config.sh           # loads hids.conf, sets defaults
│   ├── rules.sh            # RULE_IMPACT / RULE_ACTION lookup tables
│   ├── alert.sh            # raise_alert(), suppression, terminal output
│   └── util.sh             # colours, tty detection, flatten(), json_escape()
├── modules/
│   ├── health.sh           # Module 1
│   ├── users.sh            # Module 2
│   ├── procnet.sh          # Module 3
│   ├── fim.sh              # Module 4
│   └── report.sh           # Module 5 summary/report
├── simulate_attack.sh      # demo + self-scoring
├── elk_ship.sh             # existing, keep
├── send_email_report.sh    # existing, keep
├── baseline/               # gitignored
├── logs/                   # gitignored
└── README.md
```

**Severity scale (ordered, exhaustive):**
`INFO` < `LOW` < `MEDIUM` < `HIGH` < `CRITICAL`
No other values. `WARNING` is removed everywhere.

**Alert function signature — this is fixed:**

```bash
raise_alert <SEVERITY> <MODULE> <RULE_ID> <MESSAGE> [<EVIDENCE>]
```

Impact and recommended action are **not** parameters. They are looked up from
`lib/rules.sh` by `RULE_ID`. This keeps call sites short and guarantees every
rule documents itself.

**Log line schema (JSONL, one object per line):**

```json
{"timestamp":"2026-08-28T14:00:03Z","rule":"FIM-006","severity":"CRITICAL","module":"fim","host":"vm01","message":"...","evidence":"...","impact":"...","action":""}
```

`elk_ship.sh` already ships this file line by line, so keeping one-object-per-line
is what makes ELK ingestion work. Do not break it.

---

## Task 1 — `lib/util.sh` (15 min)

Create with exactly these functions:

```bash
# Returns 0 if stdout is an interactive terminal, 1 otherwise.
is_tty()

# Collapses newlines, carriage returns and tabs into single spaces, squeezes runs.
flatten() { : "$1" -> stdout ; }

# Escapes backslashes and double quotes for safe embedding in a JSON string.
json_escape() { : "$1" -> stdout ; }

# Prints text in the given colour when stdout is a TTY, plain otherwise.
# Colours: INFO=default LOW=cyan MEDIUM=yellow HIGH=red CRITICAL=bold-red-reverse
colourise() { : "$severity" "$text" -> stdout ; }
```

Acceptance: `flatten "$(who)"` returns a single line. `json_escape 'a"b\\c'`
returns `a\"b\\\\c`.

---

## Task 2 — `config/hids.conf` + `lib/config.sh` (20 min)

`config/hids.conf` — plain `KEY=value`, sourced. Contents:

```bash
# --- Module 1 thresholds ---
CPU_PCT_WARN=85
LOAD_PER_CORE_WARN=1.0
LOAD_PER_CORE_CRIT=2.0
MEM_PCT_WARN=90
SWAP_PCT_WARN=50
DISK_PCT_WARN=85
DISK_PCT_CRIT=95
INODE_PCT_WARN=90

# --- Module 2 thresholds ---
FAILED_LOGIN_WARN=5
FAILED_LOGIN_CRIT=20
FAILED_LOGIN_WINDOW_MIN=10
PRIVILEGED_GROUPS="sudo wheel adm docker"

# --- Module 3 whitelists ---
ALLOWED_LISTEN_PORTS="22 80 443 53 631"
SUSPICIOUS_BINARIES="nc ncat socat nmap masscan"
WRITABLE_EXEC_DIRS="/tmp /var/tmp /dev/shm /run/shm"

# --- Module 4 ---
FIM_TIER1="/etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/ssh/sshd_config /root/.ssh/authorized_keys"
FIM_TIER2="/etc/crontab /etc/hosts /etc/resolv.conf /etc/rc.local /etc/ld.so.preload"
FIM_TIER2_DIRS="/etc/cron.d /etc/sudoers.d /etc/systemd/system"

# --- Module 5 ---
SUPPRESS_WINDOW_LOW=3600
SUPPRESS_WINDOW_HIGH=900
MAX_ALERTS_PER_RUN=50
```

`lib/config.sh` — one function `load_config()` that sources
`config/hids.conf` if present, then applies the same values as defaults for any
variable still unset (use `: "${VAR:=default}"`). Must not fail if the config
file is missing.

---

## Task 3 — `lib/rules.sh` (25 min)

Two Bash associative arrays keyed by rule ID. This is where the `+++ Impact
description / Recommended Action` requirement lives.

```bash
declare -A RULE_IMPACT
declare -A RULE_ACTION

RULE_IMPACT[USR-005]="An account with root-equivalent privileges was created or modified."
RULE_ACTION[USR-005]="Lock the account (passwd -l), inspect /var/log/auth.log for its creation, and review sudo history."
```

Populate all rule IDs listed in Task 5–8 below. Add two accessor functions:

```bash
# Returns the impact description for a rule ID, or a generic fallback.
rule_impact() { : "$rule_id" -> stdout ; }

# Returns the recommended action for a rule ID, or a generic fallback.
rule_action() { : "$rule_id" -> stdout ; }
```

---

## Task 4 — `lib/alert.sh` (40 min) — **the keystone, do not skip**

```bash
# Initialises log/baseline/state directories and the alert counter.
init_alerting()

# Returns 0 if this rule+evidence fired within its suppression window.
# State file: state/suppress.db, format: <key>\t<epoch>\t<count>
suppressed() { : "$rule_id" "$evidence" ; }

# Emits one alert: flattens evidence, looks up impact/action, writes one JSONL
# line to logs/hids.log, prints a coloured terminal line, tracks max severity.
raise_alert() { : "$sev" "$module" "$rule" "$msg" "$evidence" ; }

# Returns the highest severity seen this run as an exit code:
# 0=clean 1=LOW/MEDIUM 2=HIGH 3=CRITICAL
max_severity_exit_code()
```

Hard requirements:
- `raise_alert` calls `flatten` then `json_escape` on **both** message and
  evidence before writing. This centrally fixes the current bug where `who`,
  `last` and `ss` output breaks the JSON.
- Suppression windows: `SUPPRESS_WINDOW_LOW` for INFO/LOW, `SUPPRESS_WINDOW_HIGH`
  for MEDIUM/HIGH, **none** for CRITICAL.
- On the first alert after a suppression window expires, include the suppressed
  count in the message: `"(repeated 12 times since 13:04)"`.
- If alert count for a run exceeds `MAX_ALERTS_PER_RUN`, emit `ALR-002` at HIGH
  and stop emitting further non-CRITICAL alerts.

---

## Task 5 — `modules/health.sh` (30 min)

```bash
# Samples /proc/stat twice one second apart and returns CPU busy percentage.
read_cpu_pct()

# Returns 1-minute load average divided by the core count, to 2 decimals.
read_load_per_core()

# Returns memory and swap usage percentages from /proc/meminfo.
read_mem_pct() ; read_swap_pct()

# Emits one INFO metrics line plus any threshold alerts.
run_health_module()
```

**Critical fix:** the current script samples `/proc/stat` once and diffs against
`PREV_TOTAL`/`PREV_IDLE`, which are shell variables that do not survive between
cron runs — CPU therefore always reports 0%. Sample twice inside one call:

```bash
read_cpu_snapshot() { awk '/^cpu /{idle=$5+$6; t=0; for(i=2;i<=NF;i++) t+=$i; print idle, t}' /proc/stat; }
read -r i1 t1 < <(read_cpu_snapshot); sleep 1; read -r i2 t2 < <(read_cpu_snapshot)
cpu=$(( 100 * ( (t2-t1) - (i2-i1) ) / (t2-t1) ))
```

Rules to implement:

| ID | Condition | Severity |
|---|---|---|
| SYS-001 | CPU ≥ `CPU_PCT_WARN` | MEDIUM |
| SYS-002 | load/core ≥ `LOAD_PER_CORE_WARN` | LOW |
| SYS-003 | load/core ≥ `LOAD_PER_CORE_CRIT` | MEDIUM |
| SYS-004 | mem ≥ `MEM_PCT_WARN` | MEDIUM |
| SYS-005 | swap ≥ `SWAP_PCT_WARN` | MEDIUM |
| SYS-006 | any fs ≥ `DISK_PCT_WARN` | LOW |
| SYS-007 | any fs ≥ `DISK_PCT_CRIT` | HIGH |
| SYS-008 | any fs inodes ≥ `INODE_PCT_WARN` | HIGH |
| SYS-100 | always — metrics snapshot | INFO |

`SYS-100` is the trend data. Emit it every run, exempt from suppression.

---

## Task 6 — `modules/users.sh` (45 min)

Incorporates the `+++ permissions, user lists, group lists, lastlog` addition.

```bash
# Aggregates btmp failures by (user, source) within the configured window.
read_failed_logins()

# Diffs getent passwd against baseline/users.txt.
check_new_accounts()

# Diffs getent group against baseline/groups.txt for privileged groups.
check_group_changes()

# Reports last login time per account via lastlog, flags never-logged-in
# accounts that suddenly have a login.
check_lastlog()

# Checks mode/owner of /etc/passwd /etc/shadow /etc/group /etc/gshadow.
check_account_file_permissions()

# Orchestrates all of the above.
run_users_module()
```

| ID | Condition | Severity |
|---|---|---|
| USR-001 | ≥ `FAILED_LOGIN_WARN` failures from one source in window | MEDIUM |
| USR-002 | ≥ `FAILED_LOGIN_CRIT` failures from one source in window | HIGH |
| USR-003 | failure burst from IP **then** success from same IP | CRITICAL |
| USR-004 | new account vs baseline | MEDIUM |
| USR-005 | UID 0 account other than `root` | CRITICAL |
| USR-006 | empty password field in `/etc/shadow` | CRITICAL |
| USR-007 | new member in a `PRIVILEGED_GROUPS` group | HIGH |
| USR-008 | shell changed from `nologin`/`false` to a real shell | HIGH |
| USR-009 | new/modified `authorized_keys` under `/home` or `/root` | HIGH |
| USR-012 | shell history file zero-length or → `/dev/null` | HIGH |
| USR-014 | `/etc/shadow` mode not `0640`/`0600`, or not owned by root | CRITICAL |
| USR-015 | `/etc/passwd` writable by non-root | CRITICAL |
| USR-016 | account with no prior lastlog entry logged in for the first time | MEDIUM |

**Fix:** the current `module_user_activity` alerts MEDIUM whenever `lastb`
returns anything at all. Replace with the aggregation above.

---

## Task 7 — `modules/procnet.sh` (45 min)

```bash
# Walks /proc/[0-9]* and emits: pid, uid, ppid, resolved exe path, cwd.
enumerate_processes()

# Flags processes running from writable dirs or with deleted binaries.
check_process_paths()

# Compares ls /proc against ps output to find hidden PIDs.
check_hidden_processes()

# Normalises listeners to "proto address:port" — no PIDs — and diffs baseline.
read_listeners()

# Orchestrates all of the above.
run_procnet_module()
```

| ID | Condition | Severity |
|---|---|---|
| PRC-001 | process `exe` inside `WRITABLE_EXEC_DIRS` | HIGH |
| PRC-002 | process `exe` symlink ends in `(deleted)` | HIGH |
| PRC-003 | UID 0 process whose parent is a shell or web server | HIGH |
| PRC-004 | `[bracketed]` name but has a real on-disk `exe` | CRITICAL |
| PRC-005 | PID in `/proc` but absent from `ps` | CRITICAL |
| PRC-006 | service account running an interactive shell | CRITICAL |
| PRC-009 | binary in `SUSPICIOUS_BINARIES` running | MEDIUM |
| NET-001 | listening port not in `ALLOWED_LISTEN_PORTS` | HIGH |
| NET-002 | listener bound `0.0.0.0` on a non-whitelisted port | HIGH |
| NET-005 | interface in promiscuous mode (`ip link | grep -i promisc`) | HIGH |

**Two fixes:**
1. Delete `SUSPICIOUS_PROCESS_NAMES` containing `bash`/`python3`/`openssl` —
   it fires constantly and catches nothing renamed. Path-based PRC-001/002 is
   the replacement.
2. Baseline listeners **without PID numbers**. The current
   `check_network_activity` stores `ss -tulnp` output including PIDs, so every
   `sshd` restart produces a false HIGH.

---

## Task 8 — `modules/fim.sh` (40 min)

```bash
# Emits "path<TAB>mode<TAB>uid<TAB>gid<TAB>size<TAB>sha256" for one file.
fingerprint_file()

# Writes baseline/fim.txt from FIM_TIER1 + FIM_TIER2 + FIM_TIER2_DIRS contents.
write_fim_baseline()

# Compares current fingerprints to baseline, reporting WHAT changed.
check_fim()

# Diffs SUID/SGID inventory. Runs only when --full is passed.
check_suid_inventory()

# Orchestrates. Accepts optional "--full" for expensive filesystem sweeps.
run_fim_module()
```

| ID | Condition | Severity |
|---|---|---|
| FIM-001 | Tier 1 file hash changed | CRITICAL |
| FIM-002 | Tier 1 file missing | CRITICAL |
| FIM-003 | Tier 2 file changed or added | HIGH |
| FIM-004 | mode changed on any monitored file | HIGH |
| FIM-005 | owner/group changed on any monitored file | HIGH |
| FIM-006 | new SUID/SGID binary vs baseline | CRITICAL |
| FIM-007 | SUID binary outside `/usr/bin /usr/sbin /bin /sbin` | CRITICAL |
| FIM-008 | `/etc/ld.so.preload` exists | CRITICAL |
| FIM-010 | new file in `/etc/cron.d` or changed `/etc/crontab` | HIGH |
| FIM-012 | monitored log file smaller than at baseline | HIGH |
| FIM-014 | no baseline existed — state unverified | MEDIUM |

Alert messages must state the transition, not just the path:
`"mode 0755 -> 4755 on /usr/bin/find"`. Vague alerts are explicitly called out
in your research as the failure mode of bad tools.

**Fix:** the current script silently creates a baseline on first run. Emit
FIM-014 instead, so a tool installed on an already-compromised host leaves a
record.

**Performance:** `find / -xdev` takes seconds to minutes. Gate it behind
`--full`; the default scheduled scan runs every minute and only sends email
when new alert IDs meet the configured severity thresholds.

---

## Task 9 — `HIDS.sh` orchestrator (30 min)

Contains **no detection logic**. Sources `lib/*.sh` then `modules/*.sh`, parses
CLI, dispatches, exits with `max_severity_exit_code`.

```
--baseline       write all baselines, emit no alerts
--once           fast checks only (health, users, procnet, fim without --full)
--full           everything including SUID sweep and world-writable scan
--report         run --once then print/write the summary
--email-report   run --once then send_email_report.sh
--minute-scan    run --once-style checks and email only for new alert IDs above thresholds
--ship-elk       run --once then elk_ship.sh --once
--simulate       run simulate_attack.sh then score detection
--install-cron   install the one-minute Linux cron schedule (see below)
--verify-log     verify alert IDs and the alert hash chain
--help
```

Cron install writes one Linux VM entry:

```
* * * * * <path>/HIDS.sh --minute-scan >/dev/null 2>&1
```

---

## Task 10 — `modules/report.sh` (20 min)

One-page summary written to `logs/hids-summary.txt` and printed on `--report`:

```
HIDS Report — vm01 — 2026-08-28 14:00:03 UTC
Duration 4.2s   Rules evaluated 61

  CRITICAL 1    HIGH 3    MEDIUM 2    LOW 4    INFO 51

CRITICAL
  [USR-005] New UID 0 account 'svc-backup'
      Impact: An account with root-equivalent privileges was created.
      Action: Lock the account, inspect auth.log, review sudo history.
HIGH
  [NET-001] New listener 0.0.0.0:8888 (/tmp/.x, pid 3122)
  [FIM-006] New SUID binary /tmp/.x

System: CPU 12%  MEM 41%  DISK 63%  LOAD/core 0.31
```

Impact and action lines come from `rule_impact` / `rule_action`.

---

## Task 11 — `simulate_attack.sh` (40 min) — **the demo centrepiece**

Runs a post-exploitation sequence, re-runs the HIDS, then scores itself.

| Step | Action | Expected rule |
|---|---|---|
| 1 | `useradd -o -u 0 svc-backup` | USR-005 |
| 2 | `cp /bin/bash /tmp/.x && chmod 4755 /tmp/.x` | FIM-006, FIM-007 |
| 3 | `/tmp/.x -c 'sleep 300' &` | PRC-001 |
| 4 | `nc -lnp 8888 &` | NET-001, NET-002 |
| 5 | `echo '* * * * * root /tmp/.x' > /etc/cron.d/x` | FIM-010 |
| 6 | append a key to `/root/.ssh/authorized_keys` | USR-009 |
| 7 | `: > ~/.bash_history` | USR-012 |
| 8 | `touch /etc/ld.so.preload` | FIM-008 |

Then:

```bash
# Greps logs/hids.log for each expected rule ID emitted after the run start
# timestamp, prints a per-step PASS/MISS table and an overall percentage.
score_detection()
```

Output ends with `Detected 9/10 rules (90%)  — missed: PRC-001`.

Ship `--cleanup` reversing every step. Print a refusal unless the environment
variable `HIDS_SIMULATE_OK=1` is set, so it cannot be run by accident.

---

## Task 12 — `README.md` (20 min)

Written for someone who did not build the tool. Must cover: what it does, install,
the six CLI flags, how to read a log line field by field, the full rule table with
impact and action, how to change thresholds in `config/hids.conf`, how to whitelist
a port, the ELK setup, and the exit codes.

---

## If you run out of time

Do Tasks 1, 4, 5, 9 and a cut-down 6/7/8 — that satisfies every must-have.
Task 11 is the highest-value optional; do it before Task 3 polish if forced to
choose, because it is what makes the demo distinctive.

---

## Prompting Copilot with this file

Work file by file. A prompt that works:

> `#file:SPEC.md` Implement Task 4, `lib/alert.sh`, exactly as specified.
> Use the function names and signatures given. Every function needs a one-line
> comment above it. Bash only, `set -uo pipefail`, no `set -e`. Do not implement
> any other task.

Then, before moving on:

> `#file:SPEC.md` `#file:lib/alert.sh` Review this against Task 4. List any
> requirement in the spec that the code does not meet. Do not rewrite it yet.

That second prompt catches most drift. Copilot degrades when asked for more than
one file at a time — resist the urge to say "now build all the modules".