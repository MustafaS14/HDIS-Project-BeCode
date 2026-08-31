#!/bin/bash
# Import HIDS Kibana visualizations and dashboards

set -euo pipefail

# Configuration from your project
ES_URL="https://my-elasticsearch-project-d17947.es.europe-west1.gcp.elastic.cloud:443"
ES_API_KEY="RDRQV1I2QUJzVDlOMmpMU3NIbkE6dkZKaEd2TmRSSjkwVUdhaUtJVkxlQQ=="

# Kibana base URL (derived from ES URL)
KIBANA_URL="${ES_URL%:*}"
KIBANA_URL="${KIBANA_URL//.es./​.kb.}"  # Convert .es. to .kb.

echo "Kibana URL: $KIBANA_URL"
echo "Importing HIDS visualizations..."

# Import the main dashboards
curl -X POST "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -H "Authorization: ApiKey $ES_API_KEY" \
  -d @kibana-visualizations.json

echo ""
echo "✅ Import complete! Check your Kibana dashboards."
echo "Dashboard name: HIDS Security Dashboard"
