#!/usr/bin/env bash
###############################################################################
# HIDS to Elasticsearch Ingestion Script
# Sends HIDS security events to Elasticsearch with proper error handling
###############################################################################

set -euo pipefail

# ========== CONFIGURATION ==========
# Update these with your Elasticsearch details
ES_URL="https://your-elasticsearch-endpoint:9200"
ES_API_KEY="your_api_key_here"  # Recommended: Use API key instead of user/pass

# OR use username/password (less secure):
# ES_USER="your-username"
# ES_PASS="your-password"

# Index configuration
INDEX_PREFIX="hids-events"
BATCH_SIZE=500  # Number of events per bulk request
LOG_FILE="/var/log/hids-ingest.log"

# ========== FUNCTIONS ==========
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

error() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" | tee -a "$LOG_FILE" >&2
}

# Function to enrich event with ECS fields and proper structure
enrich_event() {
  local raw_event="$1"
  local host_name
  local host_ip

  host_name="$(hostname)"
  host_ip="$(hostname -I | awk '{print $1}')"

  # Transform your HIDS event into ECS-compliant format
  echo "$raw_event" | jq -c \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" \
    --arg hostname "$host_name" \
    --arg hostip "$host_ip" \
    '
    {
      "@timestamp": (if .timestamp then .timestamp else $timestamp end),
      "event": {
        "severity": (.severity // "medium"),
        "module": (.module // "unknown"),
        "category": ["host"],
        "type": ["info"]
      },
      "message": .message,
      "host": {
        "name": $hostname,
        "ip": $hostip
      },
      "file": (if .file_path then {
        "path": .file_path,
        "hash": (if .file_hash then {"sha256": .file_hash} else null end)
      } else null end),
      "process": (if .process_name then {
        "name": .process_name,
        "pid": (.process_pid // null),
        "command_line": (.process_cmdline // null)
      } else null end),
      "network": (if .network_port then {
        "transport": (.network_protocol // "tcp"),
        "port": .network_port
      } else null end),
      "user": (if .user_name then {
        "name": .user_name,
        "id": (.user_id // null)
      } else null end),
      "hids": {
        "baseline_hash": (.baseline_hash // null),
        "scan_id": (.scan_id // null)
      },
      "tags": (.tags // ["hids"])
    }
    | walk(if type == "object" then with_entries(select(.value != null)) else . end)
    '
}

# Function to send bulk request
send_bulk() {
  local bulk_data="$1"
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
    local errors
    errors="$(echo "$body" | jq -r '.errors')"

    if [ "$errors" = "false" ]; then
      local indexed
      indexed="$(echo "$body" | jq -r '.items | length')"
      log "Successfully indexed $indexed events to $index_name"
      return 0
    else
      local failed
      failed="$(echo "$body" | jq -r '[.items[] | select(.index.error)] | length')"
      error "Partial failure: $failed events failed to index"
      echo "$body" | jq '.items[] | select(.index.error)' >> "$LOG_FILE"
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
  local enriched

  while IFS= read -r line; do
    # Skip empty lines
    [ -z "$line" ] && continue

    # Enrich the event
    enriched="$(enrich_event "$line")"

    # Build bulk payload (index action + document)
    bulk_payload+='{"index":{}}'
    bulk_payload+=$'\n'
    bulk_payload+="$enriched"
    bulk_payload+=$'\n'

    count=$((count + 1))
    total=$((total + 1))

    # Send batch when reaching BATCH_SIZE
    if [ $count -ge $BATCH_SIZE ]; then
      send_bulk "$bulk_payload"
      bulk_payload=""
      count=0
    fi
  done < "$input_file"

  # Send remaining events
  if [ $count -gt 0 ]; then
    send_bulk "$bulk_payload"
  fi

  log "Ingestion complete. Total events processed: $total"
}

# Run main function
main "$@"
