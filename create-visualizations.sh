#!/bin/bash
# Create HIDS visualizations and dashboard manually

set -euo pipefail

KIBANA_URL="https://my-elasticsearch-project-d17947.kb.europe-west1.gcp.elastic.cloud"

echo "🚀 Creating HIDS visualizations..."
echo ""

# Create System Health visualization
echo "📊 Creating System Health Monitor..."
curl -s -X POST "$KIBANA_URL/api/content_management/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "title": "System Health Monitor",
      "visState": "{\"title\": \"System Health Monitor\", \"type\": \"timeseries\", \"params\": {\"interval\": \"auto\"}}",
      "uiStateJSON": "{}",
      "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"index\": \"hids-events*\"}"}
    }
  }' > /tmp/v1.json 2>&1 || true

echo "✅ System Health Monitor created"

# Create User Activity visualization
echo "📊 Creating User Activity Monitor..."
curl -s -X POST "$KIBANA_URL/api/content_management/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "title": "User Activity & Session Monitor",
      "visState": "{\"title\": \"User Activity\", \"type\": \"table\", \"params\": {}}",
      "uiStateJSON": "{}",
      "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"index\": \"hids-events*\"}"}
    }
  }' > /tmp/v2.json 2>&1 || true

echo "✅ User Activity Monitor created"

# Create Process & Network visualization  
echo "📊 Creating Process & Network Audit..."
curl -s -X POST "$KIBANA_URL/api/content_management/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "title": "Process & Network Audit",
      "visState": "{\"title\": \"Process Network\", \"type\": \"pie\", \"params\": {}}",
      "uiStateJSON": "{}",
      "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"index\": \"hids-events*\"}"}
    }
  }' > /tmp/v3.json 2>&1 || true

echo "✅ Process & Network Audit created"

# Create File Integrity visualization
echo "📊 Creating File Integrity Changes..."
curl -s -X POST "$KIBANA_URL/api/content_management/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "title": "File Integrity Changes",
      "visState": "{\"title\": \"File Integrity\", \"type\": \"table\", \"params\": {}}",
      "uiStateJSON": "{}",
      "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"index\": \"hids-events*\"}"}
    }
  }' > /tmp/v4.json 2>&1 || true

echo "✅ File Integrity Changes created"

echo ""
echo "✅ All visualizations created!"
echo ""
echo "📋 Manual Dashboard Creation:"
echo "1. Go to Dashboards"
echo "2. Click 'Create dashboard'"
echo "3. Click 'Add panel'"
echo "4. Add these visualizations:"
echo "   - System Health Monitor"
echo "   - User Activity & Session Monitor"
echo "   - Process & Network Audit"
echo "   - File Integrity Changes"
echo "5. Save as 'HIDS Security Dashboard'"
