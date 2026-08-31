#!/bin/bash
# Setup and ship HIDS data to Elasticsearch

set -euo pipefail

# Your Elasticsearch credentials
export ELASTIC_URL="https://my-elasticsearch-project-d17947.es.europe-west1.gcp.elastic.cloud:443"
export ELASTIC_API_KEY="RDRQV1I2QUJzVDlOMmpMU3NIbkE6dkZKaEd2TmRSSjkwVUdhaUtJVkxlQQ=="
export ELASTIC_INDEX="hids-alerts"

echo "🚀 Setting up Elasticsearch connection..."
echo "URL: $ELASTIC_URL"
echo "Index: $ELASTIC_INDEX"
echo ""

# Ship the logs
echo "📤 Shipping HIDS logs to Elasticsearch..."
bash ./HIDS.sh --ship-elk

echo ""
echo "✅ Done! Your HIDS logs are now in Elasticsearch"
echo ""
echo "Next steps:"
echo "1. Go to Kibana: https://my-elasticsearch-project-d17947.kb.europe-west1.gcp.elastic.cloud"
echo "2. Create index pattern for 'hids-*'"
echo "3. Import dashboards (kibana-visualizations.json)"
