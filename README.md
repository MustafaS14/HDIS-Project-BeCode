# HIDS Bash Project

HIDS is a small host-based intrusion detection tool implemented in Bash. It runs regular lightweight checks (health, users, processes/net, and file integrity), records one-line JSON alerts to a log, and can produce a human summary for reporting.

This repository follows the SPEC contract: all detection is Bash-only and uses only standard Linux utilities (`awk`, `sed`, `grep`, `find`, `sha256sum`, `ps`, `ss`, `who`, `last`, `lastb`, `lastlog`, `getent`, `df`, `crontab`, `hostname`, `ip`).

Usage (entrypoint)
- `./hids.sh --baseline`    : write baselines for files, listeners, users (no alerts)
- `./hids.sh --once`        : run the fast checks and write alerts to `logs/hids.log`
- `./hids.sh --full`        : run everything including expensive SUID inventory
- `./hids.sh --report`      : run `--once` then print/write a one-page summary
- `./hids.sh --email-report`: run `--once` then call `send_email_report.sh` if present
- `./hids.sh --ship-elk`    : run `--once` then call `elk/elk_ship.sh --once`
- `./hids.sh --install-cron`: install cron entries for periodic runs

Log format (JSONL)
Each alert is one JSON object per line in `logs/hids.log`. Fields:

 - `timestamp` : ISO 8601 UTC string
 - `rule`      : rule ID (e.g. `FIM-006`)
 - `severity`  : one of `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
 - `module`    : module name (health, users, procnet, fim, etc.)
 - `host`      : hostname
 - `message`   : flattened, escaped message
 - `evidence`  : flattened, escaped evidence string
 - `impact`    : impact text from `lib/rules.sh`
 - `action`    : recommended action text from `lib/rules.sh`

Example line:
```
{"timestamp":"2026-08-31T12:02:55Z","rule":"FIM-006","severity":"CRITICAL","module":"fim","host":"vm01","message":"New SUID binary /tmp/.x","evidence":"path=/tmp/.x sha256=...","impact":"A new SUID/SGID binary appeared.","action":"Inspect the binary and remove SUID bit if unauthorized."}
```

Rules, impacts and actions
The full rule list lives in `lib/rules.sh`. Brief highlights (impact → recommended action):

- `USR-005`: An account with root-equivalent privileges was created. → Lock the account, inspect auth logs, review sudo history.
- `FIM-006`: New SUID/SGID binary vs baseline. → Inspect and remove SUID/SGID if unauthorized.
- `FIM-007`: SUID binary outside trusted dirs. → Treat as suspicious, isolate and investigate.
- `PRC-001`: Process running from writable dir. → Quarantine and investigate process provenance.
- `PRC-002`: Process executable deleted from disk. → Capture evidence from memory and investigate.
- `PRC-004`: Bracketed kernel-style name with a real exe. → Inspect executable path vs. process name.
- `PRC-005`: PID in `/proc` but missing from `ps`. → Capture evidence — possible hidden process.
- `NET-001`: Listener on a non-whitelisted port. → Identify process and confirm service.
- `NET-002`: Listener bound to `0.0.0.0` on non-whitelisted port. → Restrict or stop service.
- `SYS-100`: Metrics snapshot (INFO). → Use for trend analysis.

You can read full impact/action strings in `lib/rules.sh`.

Configuration
Edit `config/hids.conf` to change thresholds and whitelists. Example keys:

- `CPU_PCT_WARN`, `LOAD_PER_CORE_WARN`, `LOAD_PER_CORE_CRIT`, `MEM_PCT_WARN`
- `FAILED_LOGIN_WARN`, `FAILED_LOGIN_CRIT`, `PRIVILEGED_GROUPS`
- `ALLOWED_LISTEN_PORTS`, `SUSPICIOUS_BINARIES`, `WRITABLE_EXEC_DIRS`
- `FIM_TIER1`, `FIM_TIER2`, `FIM_TIER2_DIRS`
- `SUPPRESS_WINDOW_LOW`, `SUPPRESS_WINDOW_HIGH`, `MAX_ALERTS_PER_RUN`

After editing `config/hids.conf`, re-run `./hids.sh --once` or restart scheduled runs.

Whitelisting a port
Add the port number to `ALLOWED_LISTEN_PORTS` in `config/hids.conf`, e.g.:

```
ALLOWED_LISTEN_PORTS="22 80 443 53 631 8888"
```

ELK / Kibana files
The ELK-related pieces live under `elk/` so it is easier to find the shipper, sample ingestion helpers, and the Kibana verification step:

- `elk/elk_ship.sh` ships new JSONL alerts from `logs/hids.log` to Elasticsearch.
- `elk/ingest_to_elastic.sh` is an alternate ingestion helper kept for reference.
- `elk/elk_snippet_from_elk.sh` contains an example ELK-oriented shell snippet.
- `Kibana` is used to create the API key and verify the `hids-alerts*` index pattern.

Use `elk/elk_ship.sh` to bulk ship new JSONL lines to Elasticsearch. Steps:

1. Create an API key in Kibana and export:
```
export ELASTIC_URL="https://..."
export ELASTIC_API_KEY="..."
export ELASTIC_INDEX="hids-alerts"
```
2. Run shipper: `./elk/elk_ship.sh --once` or `./hids.sh --ship-elk`.
3. Verify ingestion in Kibana with index pattern `hids-alerts*`.

Simulation
The demo script `simulate_attack.sh` performs a sequence of actions to exercise detections. It refuses to run unless you set `HIDS_SIMULATE_OK=1` in the environment to avoid accidental destructive changes. It records created files and PIDs under `state/` and supports `--cleanup` to try to revert changes.

Exit codes
- `0`: clean or INFO-only
- `1`: LOW/MEDIUM alerts present
- `2`: HIGH alerts present
- `3`: CRITICAL alerts present

Where to start
1. `./hids.sh --baseline` — create baselines (quiet)
2. `./hids.sh --once` — run fast checks and write alerts to `logs/hids.log`
3. `./hids.sh --report` — generate a human summary in `logs/hids-summary.txt`

If you want, I can expand the README with examples of reading `logs/hids.log` with `jq`, or add a `CONTRIBUTING.md` with development notes.
