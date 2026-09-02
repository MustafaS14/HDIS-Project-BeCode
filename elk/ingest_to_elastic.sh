#!/usr/bin/env bash
###############################################################################
# HIDS to Elasticsearch Ingestion Script
# Sends HIDS security events to Elasticsearch with native Bash tools only
###############################################################################

set -euo pipefail

# ========== CONFIGURATION ==========
# Update these with your Elasticsearch details
ES_URL="https://my-elasticsearch-project-d17947.es.europe-west1.gcp.elastic.cloud:443"
ES_API_KEY="RDRQV1I2QUJzVDlOMmpMU3NIbkE6dkZKaEd2TmRSSjkwVUdhaUtJVkxlQQ=="  # Recommended: Use API key instead of user/pass

# OR use username/password (less secure):
# ES_USER="your-username"
# ES_PASS="your-password"

# Index configuration
INDEX_PREFIX="hids-events"
BATCH_SIZE=500  # Number of events per bulk request
LOG_FILE="${LOG_FILE:-/var/log/hids-ingest.log}"

# Fallback log location if default location is not writable
if ! touch "$LOG_FILE" 2>/dev/null; then
  LOG_FILE=".hids/hids-ingest.log"
fi

# ========== FUNCTIONS ==========
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

error() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" | tee -a "$LOG_FILE" >&2
}

# Accept only non-empty JSON object lines to keep bulk ingestion robust.
prepare_event() {
  local raw_event="$1"
  if printf '%s' "$raw_event" | grep -Eq '^[[:space:]]*\{.*\}[[:space:]]*$'; then
    printf '%s\n' "$raw_event"
    return 0
  fi
  return 1
}

# Function to send bulk request
send_bulk() {
  local bulk_data="$1"
  local batch_count="$2"
  local index_name="${INDEX_PREFIX}-$(date +%Y.%m.%d)"
  local response

  if [ -n "${ES_API_KEY:-}" ]; then
    # Using API Key (recommended)
    response="$(echo "$bulk_data" | curl -s -w "\n%{http_code}" \
      -H "Authorization: ApiKey $ES_API_KEY" \
      -H "Content-Type: application/x-ndjson" \
      -X POST "${ES_URL}/${index_name}/_bulk" \
      --data-binary @-)"
  else
    # Using username/password
    response="$(echo "$bulk_data" | curl -s -w "\n%{http_code}" \
      -u "${ES_USER}:${ES_PASS}" \
      -H "Content-Type: application/x-ndjson" \
      -X POST "${ES_URL}/${index_name}/_bulk" \
      --data-binary @-)"
  fi

  local http_code
  local body
  http_code="$(echo "$response" | tail -n1)"
  body="$(echo "$response" | sed '$d')"

  if [ "$http_code" -eq 200 ] || [ "$http_code" -eq 201 ]; then
    if printf '%s' "$body" | grep -Eq '"errors"[[:space:]]*:[[:space:]]*false'; then
      log "Successfully indexed ${batch_count} events to $index_name"
      return 0
    else
      error "Partial failure detected in Elasticsearch bulk response"
      echo "$body" >> "$LOG_FILE"
      return 1
    fi
  else
    error "HTTP $http_code error from Elasticsearch"
    echo "$body" >> "$LOG_FILE"
    return 1
  fi
}

# ========== MAIN LOGIC ==========
main() {
  local input_file="${1:-}"

  if [ -z "$input_file" ]; then
    error "Usage: $0 <events_json_file>"
    exit 1
  fi

  if [ ! -f "$input_file" ]; then
    error "Input file not found: $input_file"
    exit 1
  fi

  log "Starting HIDS event ingestion from: $input_file"

  local bulk_payload=""
  local count=0
  local total=0
  local skipped=0
  local prepared

  if ! command -v curl >/dev/null 2>&1; then
    error "curl is required but not found"
    exit 1
  fi

  while IFS= read -r line; do
    # Skip empty lines
    [ -z "$line" ] && continue

    if ! prepared="$(prepare_event "$line")"; then
      skipped=$((skipped + 1))
      error "Skipping non-JSON log line during ingestion"
      continue
    fi

    # Build bulk payload (index action + document)
    bulk_payload+='{"index":{}}'
    bulk_payload+=$'\n'
    bulk_payload+="$prepared"
    bulk_payload+=$'\n'

    count=$((count + 1))
    total=$((total + 1))

    # Send batch when reaching BATCH_SIZE
    if [ $count -ge $BATCH_SIZE ]; then
      send_bulk "$bulk_payload" "$count"
      bulk_payload=""
      count=0
    fi
  done < "$input_file"

  # Send remaining events
  if [ $count -gt 0 ]; then
    send_bulk "$bulk_payload" "$count"
  fi

  log "Ingestion complete. Total events processed: $total, skipped: $skipped"
}

# Run main function
main "$@"
