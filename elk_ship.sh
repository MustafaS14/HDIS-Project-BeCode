#!/usr/bin/env bash
set -u
set -o pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${PROJECT_ROOT}/.hids"
LOG_FILE="${LOG_FILE:-${STATE_DIR}/hids.log}"
OFFSET_FILE="${OFFSET_FILE:-${STATE_DIR}/elk_ship.offset}"
ELASTIC_URL="${ELASTIC_URL:-}"
ELASTIC_API_KEY="${ELASTIC_API_KEY:-}"
ELASTIC_INDEX="${ELASTIC_INDEX:-hids-alerts}"

print_help() {
  cat <<'USAGE'
HIDS -> Elasticsearch shipper (Bash + curl)

Usage:
  ./elk_ship.sh --once
  ./elk_ship.sh --help

Required environment variables:
  ELASTIC_URL      Example: https://my-deployment.es.region.gcp.elastic-cloud.com:443
  ELASTIC_API_KEY  Base64 API key from Elastic

Optional environment variables:
  ELASTIC_INDEX    Target index name (default: hids-alerts)
  LOG_FILE         Source log file (default: .hids/hids.log)
  OFFSET_FILE      Offset state file (default: .hids/elk_ship.offset)
USAGE
}

ensure_state() {
  mkdir -p "${STATE_DIR}"
  [ -e "${LOG_FILE}" ] || touch "${LOG_FILE}"
  if [ ! -f "${OFFSET_FILE}" ]; then
    echo "0" > "${OFFSET_FILE}"
  fi
}

ship_once() {
  ensure_state

  if [ -z "${ELASTIC_URL}" ] || [ -z "${ELASTIC_API_KEY}" ]; then
    echo "ELASTIC_URL and ELASTIC_API_KEY must be set." >&2
    return 1
  fi

  local last_offset
  last_offset="$(cat "${OFFSET_FILE}" 2>/dev/null || echo 0)"
  if ! [[ "${last_offset}" =~ ^[0-9]+$ ]]; then
    last_offset=0
  fi

  local total_lines
  total_lines="$(wc -l < "${LOG_FILE}" | tr -d ' ')"

  if [ "${total_lines}" -le "${last_offset}" ]; then
    echo "No new log lines to ship."
    return 0
  fi

  local start_line=$((last_offset + 1))
  local payload_file
  payload_file="$(mktemp)"

  # Build NDJSON bulk payload: action line + source line for each new event.
  awk -v idx="${ELASTIC_INDEX}" 'NR >= start { if (length($0) > 0) { printf("{\"index\":{\"_index\":\"%s\"}}\n%s\n", idx, $0) } }' start="${start_line}" "${LOG_FILE}" > "${payload_file}"

  if [ ! -s "${payload_file}" ]; then
    rm -f "${payload_file}"
    echo "No non-empty events found to ship."
    echo "${total_lines}" > "${OFFSET_FILE}"
    return 0
  fi

  local response_file
  response_file="$(mktemp)"
  local http_code

  http_code="$(curl -sS -o "${response_file}" -w "%{http_code}" \
    -X POST "${ELASTIC_URL}/_bulk" \
    -H "Authorization: ApiKey ${ELASTIC_API_KEY}" \
    -H "Content-Type: application/x-ndjson" \
    --data-binary @"${payload_file}")"

  if [ "${http_code}" != "200" ] && [ "${http_code}" != "201" ]; then
    echo "Elasticsearch bulk request failed (HTTP ${http_code})." >&2
    cat "${response_file}" >&2
    rm -f "${payload_file}" "${response_file}"
    return 1
  fi

  if ! grep -Eq '"errors"[[:space:]]*:[[:space:]]*false' "${response_file}"; then
    echo "Elasticsearch accepted request but returned item errors." >&2
    cat "${response_file}" >&2
    rm -f "${payload_file}" "${response_file}"
    return 1
  fi

  echo "${total_lines}" > "${OFFSET_FILE}"
  echo "Shipped $((total_lines - last_offset)) event(s) to index ${ELASTIC_INDEX}."

  rm -f "${payload_file}" "${response_file}"
  return 0
}

main() {
  case "${1:---help}" in
    --once)
      ship_once
      ;;
    --help|-h)
      print_help
      ;;
    *)
      print_help
      return 1
      ;;
  esac
}

main "$@"
