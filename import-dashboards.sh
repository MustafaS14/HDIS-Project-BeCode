#!/bin/bash
# Direct Kibana API import for HIDS visualizations

set -euo pipefail

KIBANA_URL="https://my-elasticsearch-project-d17947.kb.europe-west1.gcp.elastic.cloud"
ES_API_KEY="RDRQV1I2QUJzVDlOMmpMU3NIbkE6dkZKaEd2TmRSSjkwVUdhaUtJVkxlQQ=="

echo "🚀 Importing HIDS dashboards to Kibana..."
echo "URL: $KIBANA_URL"
echo ""

# Create a temporary file with the JSON content
TEMP_FILE=$(mktemp)
cat > "$TEMP_FILE" << 'EOF'
{
  "version": "8.0.0",
  "objects": [
    {
      "type": "visualization",
      "id": "hids-system-health",
      "attributes": {
        "title": "System Health Monitor",
        "visState": {
          "title": "System Health Monitor",
          "type": "timeseries",
          "params": {
            "interval": "auto",
            "addLegend": true,
            "addGrid": true,
            "showLegend": true,
            "legendPosition": "bottom",
            "seriesParams": [
              {
                "show": true,
                "type": "area",
                "name": "CPU Usage",
                "valueAxis": "ValueAxis-1"
              },
              {
                "show": true,
                "type": "area",
                "name": "Memory Usage",
                "valueAxis": "ValueAxis-2"
              }
            ],
            "valueAxes": [
              {
                "id": "ValueAxis-1",
                "position": "left",
                "scale": {
                  "type": "linear"
                }
              },
              {
                "id": "ValueAxis-2",
                "position": "right",
                "scale": {
                  "type": "linear"
                }
              }
            ],
            "categoryAxes": [
              {
                "id": "CategoryAxis-1",
                "position": "bottom",
                "type": "date"
              }
            ]
          },
          "aggs": [
            {
              "id": "1",
              "enabled": true,
              "type": "date_histogram",
              "schema": "segment",
              "params": {
                "field": "timestamp",
                "interval": "auto"
              }
            },
            {
              "id": "2",
              "enabled": true,
              "type": "avg",
              "schema": "metric",
              "params": {
                "field": "cpu_usage"
              }
            },
            {
              "id": "3",
              "enabled": true,
              "type": "avg",
              "schema": "metric",
              "params": {
                "field": "memory_usage"
              }
            }
          ]
        },
        "uiStateJSON": "{}",
        "kibanaSavedObjectMeta": {
          "searchSourceJSON": "{\"index\": \"hids-events*\", \"query\": {\"match_all\": {}}, \"filter\": [{\"match\": {\"module\": {\"query\": \"system_health\"}}}]}"
        }
      }
    },
    {
      "type": "visualization",
      "id": "hids-user-activity",
      "attributes": {
        "title": "User Activity & Session Monitor",
        "visState": {
          "title": "User Activity & Session Monitor",
          "type": "table",
          "params": {
            "perPage": 10,
            "showPartialRows": false,
            "showMetricsAtAllLevels": false,
            "showTotal": false,
            "totalFunc": "sum",
            "percentageCol": ""
          },
          "aggs": [
            {
              "id": "1",
              "enabled": true,
              "type": "date_histogram",
              "schema": "bucket",
              "params": {
                "field": "timestamp",
                "interval": "1h"
              }
            },
            {
              "id": "2",
              "enabled": true,
              "type": "terms",
              "schema": "bucket",
              "params": {
                "field": "message.keyword",
                "size": 10,
                "order": "desc",
                "orderBy": "_count"
              }
            },
            {
              "id": "3",
              "enabled": true,
              "type": "cardinality",
              "schema": "metric",
              "params": {
                "field": "message.keyword"
              }
            }
          ]
        },
        "uiStateJSON": "{}",
        "kibanaSavedObjectMeta": {
          "searchSourceJSON": "{\"index\": \"hids-events*\", \"query\": {\"match_all\": {}}, \"filter\": [{\"terms\": {\"module\": [\"user_activity\", \"user_monitor\"]}}]}"
        }
      }
    },
    {
      "type": "visualization",
      "id": "hids-process-network-audit",
      "attributes": {
        "title": "Process & Network Audit",
        "visState": {
          "title": "Process & Network Audit",
          "type": "pie",
          "params": {
            "addLegend": true,
            "addTooltip": true,
            "isDonut": true,
            "legendPosition": "right"
          },
          "aggs": [
            {
              "id": "1",
              "enabled": true,
              "type": "terms",
              "schema": "segment",
              "params": {
                "field": "severity.keyword",
                "size": 10,
                "order": "desc",
                "orderBy": "_count"
              }
            },
            {
              "id": "2",
              "enabled": true,
              "type": "count",
              "schema": "metric"
            }
          ]
        },
        "uiStateJSON": "{}",
        "kibanaSavedObjectMeta": {
          "searchSourceJSON": "{\"index\": \"hids-events*\", \"query\": {\"match_all\": {}}, \"filter\": [{\"terms\": {\"module\": [\"process_network\", \"process_monitor\", \"network_monitor\"]}}]}"
        }
      }
    },
    {
      "type": "visualization",
      "id": "hids-file-integrity",
      "attributes": {
        "title": "File Integrity Changes",
        "visState": {
          "title": "File Integrity Changes",
          "type": "table",
          "params": {
            "perPage": 20,
            "showPartialRows": false,
            "showMetricsAtAllLevels": false,
            "showTotal": false,
            "totalFunc": "sum",
            "percentageCol": ""
          },
          "aggs": [
            {
              "id": "1",
              "enabled": true,
              "type": "date_histogram",
              "schema": "bucket",
              "params": {
                "field": "timestamp",
                "interval": "auto"
              }
            },
            {
              "id": "2",
              "enabled": true,
              "type": "terms",
              "schema": "bucket",
              "params": {
                "field": "severity.keyword",
                "size": 5,
                "order": "desc",
                "orderBy": "_count"
              }
            },
            {
              "id": "3",
              "enabled": true,
              "type": "count",
              "schema": "metric"
            }
          ]
        },
        "uiStateJSON": "{}",
        "kibanaSavedObjectMeta": {
          "searchSourceJSON": "{\"index\": \"hids-events*\", \"query\": {\"match_all\": {}}, \"filter\": [{\"match\": {\"module\": {\"query\": \"file_integrity\"}}}]}"
        }
      }
    },
    {
      "type": "dashboard",
      "id": "hids-security-dashboard",
      "attributes": {
        "title": "HIDS Security Dashboard",
        "description": "Comprehensive view of Host Intrusion Detection System events and alerts",
        "panelsJSON": "[{\"version\": \"8.0.0\", \"gridData\": {\"x\": 0, \"y\": 0, \"w\": 24, \"h\": 15}, \"type\": \"visualization\", \"id\": \"hids-system-health\", \"embeddableConfig\": {}}, {\"version\": \"8.0.0\", \"gridData\": {\"x\": 24, \"y\": 0, \"w\": 24, \"h\": 15}, \"type\": \"visualization\", \"id\": \"hids-user-activity\", \"embeddableConfig\": {}}, {\"version\": \"8.0.0\", \"gridData\": {\"x\": 0, \"y\": 15, \"w\": 24, \"h\": 15}, \"type\": \"visualization\", \"id\": \"hids-process-network-audit\", \"embeddableConfig\": {}}, {\"version\": \"8.0.0\", \"gridData\": {\"x\": 24, \"y\": 15, \"w\": 24, \"h\": 15}, \"type\": \"visualization\", \"id\": \"hids-file-integrity\", \"embeddableConfig\": {}}]",
        "timeRestore": true,
        "timeFrom": "now-24h",
        "timeTo": "now"
      }
    }
  ]
}
EOF

# Use curl with proper error handling
HTTP_CODE=$(curl -s -w "%{http_code}" -o /tmp/kibana_response.txt \
  -X POST "$KIBANA_URL/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d @"$TEMP_FILE")

echo "HTTP Response: $HTTP_CODE"
echo ""

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
  echo "✅ SUCCESS! Dashboards imported"
  cat /tmp/kibana_response.txt | head -20
else
  echo "❌ Import failed (HTTP $HTTP_CODE)"
  echo "Response:"
  cat /tmp/kibana_response.txt
fi

rm -f "$TEMP_FILE" /tmp/kibana_response.txt

echo ""
echo "Next step: Go to Dashboards and look for 'HIDS Security Dashboard'"
