# HIDS Merge Notes

Summary
- The repo now matches the ELK folder grouping requested in the merge: the ELK-related scripts live under `elk/`.
- The main runtime entrypoints still work from the repository root, but their ELK calls now point to `elk/elk_ship.sh`.
- `HIDS.sh` was updated to rename the combined process/network audit module to `system_audit` for clarity.

Current layout to keep during future merges
- `elk/elk_ship.sh`
- `elk/ingest_to_elastic.sh`
- `elk/elk_snippet_from_elk.sh`
- `HIDS.sh`
- `hids.sh`
- `README.md`
- `SPEC.md`

What to verify after merging
- `HIDS.sh`: confirm the `system_audit` rename is still wired into `run_checks()` and that `ship_after_scan()` points at `elk/elk_ship.sh`.
- `hids.sh`: confirm `--ship-elk` still dispatches to `elk/elk_ship.sh`.
- `README.md`: confirm every ELK reference uses the `elk/` folder path.
- `SPEC.md`: confirm the documented directory tree matches the repository tree.
- `elk/elk_ship.sh`: confirm the script is executable and still ships `logs/hids.log` correctly.
- `elk/ingest_to_elastic.sh` and `elk/elk_snippet_from_elk.sh`: confirm they are retained as reference helpers only and are not called by the main entrypoints.

Quick checks
- `bash -n HIDS.sh`
- `bash -n hids.sh`
- `bash -n elk/elk_ship.sh`
- `bash -n elk/ingest_to_elastic.sh`
- `bash -n elk/elk_snippet_from_elk.sh`
- `bash hids.sh --help`
- `bash hids.sh --ship-elk`

Known merge-sensitive spots
- Root-level `elk_ship.sh`, `elk_snippet_from_elk.sh`, and `ingest_to_elastic.sh` were removed in favor of the `elk/` folder.
- If the main repo still contains old references to those root-level paths, update them to `elk/...`.
- If another branch reintroduces the old names, prefer the foldered layout so the ELK files stay grouped together.


