# Kibana Visualizations Setup Guide for HIDS

This guide explains how to import and use the 4 HIDS visualizations in Kibana.

## Visualizations Overview

### 1. **System Health Monitor**
- **Type**: Time Series Chart
- **Purpose**: Tracks CPU, Memory, and Disk usage over time
- **Module**: `system_health`
- **Metrics**: CPU%, MEM%, DISK%, Load Average

### 2. **User Activity & Session Monitor**
- **Type**: Table/Data Grid
- **Purpose**: Shows active user sessions and login history
- **Modules**: `user_activity`, `user_monitor`
- **Metrics**: Session count, login events, user changes

### 3. **Process & Network Audit**
- **Type**: Pie Chart (Donut)
- **Purpose**: Visualizes severity distribution of process and network events
- **Modules**: `process_network`, `process_monitor`, `network_monitor`
- **Metrics**: Event count by severity (HIGH, MEDIUM, LOW)

### 4. **File Integrity Changes**
- **Type**: Table/Data Grid
- **Purpose**: Lists all file integrity violations with severity
- **Module**: `file_integrity`
- **Metrics**: Changed/deleted files, integrity violations by severity

---

## Installation Steps

### Step 1: Create the Index Template (Optional but Recommended)

Apply the mapping template to optimize your Elasticsearch index:

```bash
curl -X PUT "https://your-elastic-url:9200/_index_template/hids-template" \
  -H "Authorization: ApiKey YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d @elasticsearch-mapping.json
```

### Step 2: Import Visualizations into Kibana

#### Option A: Manual Import via Kibana UI
1. Open Kibana → **Stack Management** → **Saved Objects**
2. Click **Import**
3. Select the `kibana-visualizations.json` file
4. Click **Import**
5. The dashboard and 4 visualizations will be created automatically

#### Option B: API Import

```bash
curl -X POST "https://your-kibana-url/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d @kibana-visualizations.json
```

### Step 3: Configure Index Pattern (if needed)

If Kibana doesn't auto-detect your index:

1. Go to **Stack Management** → **Index Patterns**
2. Click **Create Index Pattern**
3. Pattern name: `hids-*`
4. Timestamp field: `timestamp`
5. Click **Create**

### Step 4: View Your Dashboard

1. Go to **Dashboards**
2. Find and click **"HIDS Security Dashboard"**
3. All 4 visualizations will load automatically

---

## Log Field Parsing

Your HIDS logs are JSON formatted. To extract CPU/MEM data for advanced analysis, you can use a Logstash pipeline or Ingest Pipeline:

### Elasticsearch Ingest Pipeline (for parsing message field)

```bash
PUT /_ingest/pipeline/hids-parser
{
  "description": "Parse HIDS system_health messages",
  "processors": [
    {
      "grok": {
        "field": "message",
        "patterns": [
          "CPU=%{NUMBER:cpu_usage:int}%% MEM=%{NUMBER:memory_usage:int}%% DISK=%{NUMBER:disk_usage:int}%%"
        ],
        "ignore_missing": true
      }
    }
  ]
}
```

Then update your elk_ship.sh to use the pipeline:

```bash
curl -X POST "${ELASTIC_URL}/${index_name}/_bulk?pipeline=hids-parser" \
  -H "Authorization: ApiKey ${ELASTIC_API_KEY}" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary @"${payload_file}"
```

---

## Real-time Monitoring Setup

Add these filters to your visualizations for real-time alerts:

**Filter for HIGH severity only:**
```json
{
  "term": {
    "severity": "HIGH"
  }
}
```

**Filter for last 1 hour:**
```json
{
  "range": {
    "timestamp": {
      "gte": "now-1h"
    }
  }
}
```

---

## Exporting & Sharing

To export dashboard as PDF or PNG:
1. Open the dashboard
2. Click **Share** → **Export PDF/PNG**
3. Configure options and export

---

## Troubleshooting

**Q: Visualizations show no data?**
- Verify data is being shipped to Elasticsearch: `curl -X GET "your-elastic-url/_cat/indices?v&h=index,docs.count"`
- Check index name matches `hids-*` pattern
- Verify timestamp format: `yyyy-MM-dd HH:mm:ss ZZZ`

**Q: CPU/Memory metrics not showing?**
- The ingest pipeline processor is required to extract these values from the message field
- Apply the ingest pipeline as shown above

**Q: Want to create more custom visualizations?**
- Use **Kibana Visualization** editor
- Select index: `hids-events*` or `hids-alerts`
- Fields available: `timestamp`, `severity`, `module`, `message`

---

## Next Steps

1. Set up **Alerts** for HIGH severity events
2. Create **Scheduled Reports** to email summaries daily
3. Configure **Anomaly Detection** for unusual patterns
4. Add **Canvas** dashboards for executive-level reporting
