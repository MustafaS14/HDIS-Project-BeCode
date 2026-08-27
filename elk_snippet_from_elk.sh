#!/usr/bin/env bash

# Reference snippet provided by Elastic tooling.
# Note: this variant requires jq and username/password auth.

# Elasticsearch connection details
ES_URL="https://your-elastic-endpoint:9200"
ES_INDEX="hids-events-$(date +%Y.%m.%d)"
ES_USER="your-user"
ES_PASS="your-password"

# Read JSON events and bulk upload
jq -c '. + {"@timestamp": now | strftime("%Y-%m-%dT%H:%M:%SZ")}' events.json | \
while IFS= read -r line; do
  echo '{"index":{}}'
  echo "$line"
done | \
curl -u "$ES_USER:$ES_PASS" \
  -H "Content-Type: application/x-ndjson" \
  -X POST "$ES_URL/$ES_INDEX/_bulk" \
  --data-binary @-
