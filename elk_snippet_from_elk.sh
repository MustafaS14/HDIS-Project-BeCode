#!/usr/bin/env bash

# ELK-inspired native variant adapted for this project.
# Uses Bash + curl and expects newline-delimited JSON input.

# Elasticsearch connection details
ES_URL="https://your-elastic-endpoint:9200"
ES_INDEX="hids-events-$(date +%Y.%m.%d)"
ES_API_KEY="your-base64-api-key"
EVENT_FILE="events.json"

# Read JSON events and bulk upload
while IFS= read -r line; do
  [ -z "$line" ] && continue
  echo '{"index":{}}'
  echo "$line"
done < "$EVENT_FILE" | \
curl -H "Authorization: ApiKey $ES_API_KEY" \
  -H "Content-Type: application/x-ndjson" \
  -X POST "$ES_URL/$ES_INDEX/_bulk" \
  --data-binary @-
