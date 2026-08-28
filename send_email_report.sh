#!/usr/bin/env bash
###############################################################################
# HIDS Email Reporter Script
# Generates a formatted security report and emails it via SMTP (curl/sendmail)
###############################################################################

set -u
set -o pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${PROJECT_ROOT}/.hids"
LOG_FILE="${LOG_FILE:-${STATE_DIR}/hids.log}"
HOSTNAME_STR="$(hostname 2>/dev/null || echo "host")"

# Email Configuration (Environment Variables or defaults)
EMAIL_TO="${EMAIL_TO:-mustafasyed82@gmail.com}"
SMTP_SERVER="${SMTP_SERVER:-smtp.gmail.com:587}"
SMTP_USER="${SMTP_USER:-}"
SMTP_PASS="${SMTP_PASS:-}"
EMAIL_ONLY_ON_ALERTS="${EMAIL_ONLY_ON_ALERTS:-false}"

print_help() {
  cat <<'USAGE'
HIDS Email Reporter

Usage:
  ./send_email_report.sh [lines_count]
  ./send_email_report.sh --help

Required Environment Variables (for sending real emails):
  EMAIL_TO          Recipient email address (e.g., user@example.com)
  SMTP_USER         SMTP sender email address (e.g., alert@example.com)
  SMTP_PASS         SMTP password / App Password

Optional Environment Variables:
  SMTP_SERVER          SMTP host and port (default: smtp.gmail.com:587)
  EMAIL_ONLY_ON_ALERTS Set to "true" to only send emails when HIGH or MEDIUM alerts exist (default: false)
  LOG_FILE             Path to hids.log (default: .hids/hids.log)

Example:
  export EMAIL_TO="your.email@gmail.com"
  export SMTP_USER="your.email@gmail.com"
  export SMTP_PASS="your-app-password"
  ./send_email_report.sh
USAGE
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  print_help
  exit 0
fi

# Determine mode and how many lines to inspect (default: --hourly 30)
REPORT_MODE="hourly"
LINES_COUNT=30

for arg in "$@"; do
  case "$arg" in
    --instant)
      REPORT_MODE="instant"
      ;;
    --hourly)
      REPORT_MODE="hourly"
      ;;
    [0-9]*)
      LINES_COUNT="$arg"
      ;;
  esac
done

if [ ! -f "${LOG_FILE}" ]; then
  echo "Log file not found at ${LOG_FILE}" >&2
  exit 1
fi

# Extract recent log entries
RECENT_EVENTS="$(tail -n "${LINES_COUNT}" "${LOG_FILE}" 2>/dev/null || true)"

if [ -z "${RECENT_EVENTS}" ]; then
  echo "No recent log events found in ${LOG_FILE}."
  exit 0
fi

# Count alert severities (safely parse integer counts under pipefail)
HIGH_COUNT=$(printf '%s\n' "${RECENT_EVENTS}" | grep -c '"severity":"HIGH"' 2>/dev/null || true)
MEDIUM_COUNT=$(printf '%s\n' "${RECENT_EVENTS}" | grep -c '"severity":"MEDIUM"' 2>/dev/null || true)
LOW_COUNT=$(printf '%s\n' "${RECENT_EVENTS}" | grep -c '"severity":"LOW"' 2>/dev/null || true)

HIGH_COUNT=$(echo "${HIGH_COUNT}" | tr -d '[:space:]')
MEDIUM_COUNT=$(echo "${MEDIUM_COUNT}" | tr -d '[:space:]')
LOW_COUNT=$(echo "${LOW_COUNT}" | tr -d '[:space:]')

HIGH_COUNT=${HIGH_COUNT:-0}
MEDIUM_COUNT=${MEDIUM_COUNT:-0}
LOW_COUNT=${LOW_COUNT:-0}

TOTAL_COUNT=$((HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT))

# Extract formatted messages for each severity level
HIGH_ALERTS=$(echo "${RECENT_EVENTS}" | grep '"severity":"HIGH"' | awk -F'"message":"' '{print $2}' | sed 's/"}$//' | sed 's/\\n/\n    /g' || true)
MEDIUM_ALERTS=$(echo "${RECENT_EVENTS}" | grep '"severity":"MEDIUM"' | awk -F'"message":"' '{print $2}' | sed 's/"}$//' | sed 's/\\n/\n    /g' || true)
LOW_ALERTS=$(echo "${RECENT_EVENTS}" | grep '"severity":"LOW"' | awk -F'"message":"' '{print $2}' | sed 's/"}$//' | sed 's/\\n/\n    /g' || true)

# Calculate fingerprint hash of high and medium alert contents
ALERT_CONTENT_STR="${HIGH_ALERTS}"$'\n'"${MEDIUM_ALERTS}"
if command -v sha256sum >/dev/null 2>&1; then
  CURRENT_CONTENT_HASH="$(printf '%s' "${ALERT_CONTENT_STR}" | sha256sum | awk '{print $1}')"
elif command -v md5sum >/dev/null 2>&1; then
  CURRENT_CONTENT_HASH="$(printf '%s' "${ALERT_CONTENT_STR}" | md5sum | awk '{print $1}')"
else
  CURRENT_CONTENT_HASH="$(printf '%s' "${ALERT_CONTENT_STR}" | cksum | awk '{print $1}')"
fi

STATE_FILE="${STATE_DIR}/last_instant_alert.state"

# Threshold & Deduplication Check for Instantaneous Alert Mode
if [ "${REPORT_MODE}" = "instant" ]; then
  if [ "${HIGH_COUNT}" -lt 1 ] && [ "${MEDIUM_COUNT}" -lt 5 ]; then
    echo "Instant alert threshold not met (Requires HIGH >= 1 or MEDIUM >= 5; Current HIGH: ${HIGH_COUNT}, MEDIUM: ${MEDIUM_COUNT}). Skipping instant email."
    rm -f "${STATE_FILE}" 2>/dev/null || true
    exit 0
  fi

  # Deduplication check: compare with previously emailed instant alert state
  SHOULD_SEND=0
  if [ -f "${STATE_FILE}" ]; then
    PREV_HIGH=$(awk 'NR==1 {print $1}' "${STATE_FILE}" 2>/dev/null || echo 0)
    PREV_MEDIUM=$(awk 'NR==1 {print $2}' "${STATE_FILE}" 2>/dev/null || echo 0)
    PREV_HASH=$(awk 'NR==2 {print $1}' "${STATE_FILE}" 2>/dev/null || echo "")

    PREV_HIGH=$(echo "${PREV_HIGH}" | tr -d '[:space:]')
    PREV_MEDIUM=$(echo "${PREV_MEDIUM}" | tr -d '[:space:]')
    PREV_HIGH=${PREV_HIGH:-0}
    PREV_MEDIUM=${PREV_MEDIUM:-0}

    # Trigger new email ONLY if:
    # 1. Number of HIGH severity alerts increased
    # 2. Number of MEDIUM severity alerts increased
    # 3. Content of the alerts changed
    if [ "${HIGH_COUNT}" -gt "${PREV_HIGH}" ]; then
      SHOULD_SEND=1
    elif [ "${MEDIUM_COUNT}" -gt "${PREV_MEDIUM}" ]; then
      SHOULD_SEND=1
    elif [ "${CURRENT_CONTENT_HASH}" != "${PREV_HASH}" ]; then
      SHOULD_SEND=1
    fi
  else
    # First time seeing an instant alert condition -> Send email
    SHOULD_SEND=1
  fi

  if [ "${SHOULD_SEND}" -eq 0 ]; then
    echo "Duplicate alert state (HIGH: ${HIGH_COUNT}, MEDIUM: ${MEDIUM_COUNT}). Severity did not increase and alert content is unchanged. Skipping duplicate instant email."
    exit 0
  fi

  # Save state after sending
  mkdir -p "${STATE_DIR}"
  printf '%s %s\n%s\n' "${HIGH_COUNT}" "${MEDIUM_COUNT}" "${CURRENT_CONTENT_HASH}" > "${STATE_FILE}"

  STAMP="$(date '+%Y-%m-%d %H:%M:%S %Z')"
  SUBJECT="🚨 [INSTANT SECURITY ALERT] ${HOSTNAME_STR} - HIGH: ${HIGH_COUNT} | MEDIUM: ${MEDIUM_COUNT}"
else
  # Hourly Report Mode (sends regular report including when only LOW severities exist)
  if [ "${EMAIL_ONLY_ON_ALERTS}" = "true" ] && [ "${HIGH_COUNT}" -eq 0 ] && [ "${MEDIUM_COUNT}" -eq 0 ]; then
    echo "No HIGH or MEDIUM alerts found. Skipping email (EMAIL_ONLY_ON_ALERTS=true)."
    exit 0
  fi
  STAMP="$(date '+%Y-%m-%d %H:%M:%S %Z')"
  SUBJECT="[HIDS Hourly Report] ${HOSTNAME_STR} Security Update - HIGH: ${HIGH_COUNT} | MEDIUM: ${MEDIUM_COUNT} | LOW: ${LOW_COUNT}"
fi

# Extract formatted messages for each severity level
HIGH_ALERTS=$(echo "${RECENT_EVENTS}" | grep '"severity":"HIGH"' | awk -F'"message":"' '{print $2}' | sed 's/"}$//' | sed 's/\\n/\n    /g' || true)
MEDIUM_ALERTS=$(echo "${RECENT_EVENTS}" | grep '"severity":"MEDIUM"' | awk -F'"message":"' '{print $2}' | sed 's/"}$//' | sed 's/\\n/\n    /g' || true)
LOW_ALERTS=$(echo "${RECENT_EVENTS}" | grep '"severity":"LOW"' | awk -F'"message":"' '{print $2}' | sed 's/"}$//' | sed 's/\\n/\n    /g' || true)

# Calculate fingerprint hash of high and medium alert contents
ALERT_CONTENT_STR="${HIGH_ALERTS}"$'\n'"${MEDIUM_ALERTS}"
if command -v sha256sum >/dev/null 2>&1; then
  CURRENT_CONTENT_HASH="$(printf '%s' "${ALERT_CONTENT_STR}" | sha256sum | awk '{print $1}')"
elif command -v md5sum >/dev/null 2>&1; then
  CURRENT_CONTENT_HASH="$(printf '%s' "${ALERT_CONTENT_STR}" | md5sum | awk '{print $1}')"
else
  CURRENT_CONTENT_HASH="$(printf '%s' "${ALERT_CONTENT_STR}" | cksum | awk '{print $1}')"
fi

STATE_FILE="${STATE_DIR}/last_instant_alert.state"

# Threshold & Deduplication Check for Instantaneous Alert Mode
if [ "${REPORT_MODE}" = "instant" ]; then
  if [ "${HIGH_COUNT}" -lt 1 ] && [ "${MEDIUM_COUNT}" -lt 5 ]; then
    echo "Instant alert threshold not met (Requires HIGH >= 1 or MEDIUM >= 5; Current HIGH: ${HIGH_COUNT}, MEDIUM: ${MEDIUM_COUNT}). Skipping instant email."
    rm -f "${STATE_FILE}" 2>/dev/null || true
    exit 0
  fi

  # Deduplication check: compare with previously emailed instant alert state
  SHOULD_SEND=0
  if [ -f "${STATE_FILE}" ]; then
    PREV_HIGH=$(awk 'NR==1 {print $1}' "${STATE_FILE}" 2>/dev/null || echo 0)
    PREV_MEDIUM=$(awk 'NR==1 {print $2}' "${STATE_FILE}" 2>/dev/null || echo 0)
    PREV_HASH=$(awk 'NR==2 {print $1}' "${STATE_FILE}" 2>/dev/null || echo "")

    PREV_HIGH=$(echo "${PREV_HIGH}" | tr -d '[:space:]')
    PREV_MEDIUM=$(echo "${PREV_MEDIUM}" | tr -d '[:space:]')
    PREV_HIGH=${PREV_HIGH:-0}
    PREV_MEDIUM=${PREV_MEDIUM:-0}

    # Trigger new email ONLY if:
    # 1. Number of HIGH severity alerts increased
    # 2. Number of MEDIUM severity alerts increased
    # 3. Content of the alerts changed
    if [ "${HIGH_COUNT}" -gt "${PREV_HIGH}" ]; then
      SHOULD_SEND=1
    elif [ "${MEDIUM_COUNT}" -gt "${PREV_MEDIUM}" ]; then
      SHOULD_SEND=1
    elif [ "${CURRENT_CONTENT_HASH}" != "${PREV_HASH}" ]; then
      SHOULD_SEND=1
    fi
  else
    # First time seeing an instant alert condition -> Send email
    SHOULD_SEND=1
  fi

  if [ "${SHOULD_SEND}" -eq 0 ]; then
    echo "Duplicate alert state (HIGH: ${HIGH_COUNT}, MEDIUM: ${MEDIUM_COUNT}). Severity did not increase and alert content is unchanged. Skipping duplicate instant email."
    exit 0
  fi

  # Save state after sending
  mkdir -p "${STATE_DIR}"
  printf '%s %s\n%s\n' "${HIGH_COUNT}" "${MEDIUM_COUNT}" "${CURRENT_CONTENT_HASH}" > "${STATE_FILE}"

  STAMP="$(date '+%Y-%m-%d %H:%M:%S %Z')"
  SUBJECT="🚨 [INSTANT SECURITY ALERT] ${HOSTNAME_STR} - HIGH: ${HIGH_COUNT} | MEDIUM: ${MEDIUM_COUNT}"
else
  # Hourly Report Mode (sends regular report including when only LOW severities exist)
  if [ "${EMAIL_ONLY_ON_ALERTS}" = "true" ] && [ "${HIGH_COUNT}" -eq 0 ] && [ "${MEDIUM_COUNT}" -eq 0 ]; then
    echo "No HIGH or MEDIUM alerts found. Skipping email (EMAIL_ONLY_ON_ALERTS=true)."
    exit 0
  fi
  STAMP="$(date '+%Y-%m-%d %H:%M:%S %Z')"
  SUBJECT="[HIDS Hourly Report] ${HOSTNAME_STR} Security Update - HIGH: ${HIGH_COUNT} | MEDIUM: ${MEDIUM_COUNT} | LOW: ${LOW_COUNT}"
fi

# Build professional HTML email payload file
PAYLOAD_FILE="$(mktemp)"

python3 - "$LOG_FILE" "$HOSTNAME_STR" "$STAMP" "$LINES_COUNT" "$REPORT_MODE" "${SMTP_USER:-hids@${HOSTNAME_STR}}" "${EMAIL_TO:-mustafasyed82@gmail.com}" "$SUBJECT" "$PAYLOAD_FILE" <<'PYEOF'
import json, html, sys, os

log_file = sys.argv[1]
hostname = sys.argv[2]
stamp = sys.argv[3]
lines_count = int(sys.argv[4])
report_mode = sys.argv[5]
smtp_user = sys.argv[6]
email_to = sys.argv[7]
subject = sys.argv[8]
payload_path = sys.argv[9]

events = []
if os.path.exists(log_file):
    with open(log_file, "r", encoding="utf-8") as f:
        raw_lines = f.readlines()[-lines_count:]
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except Exception:
            pass

high_events = [e for e in events if e.get("severity") == "HIGH"]
medium_events = [e for e in events if e.get("severity") == "MEDIUM"]
low_events = [e for e in events if e.get("severity") == "LOW"]

high_count = len(high_events)
medium_count = len(medium_events)
low_count = len(low_events)
total_count = len(events)

def build_rows(event_list, border_color="#e2e8f0"):
    if not event_list:
        return f'<tr><td colspan="3" style="padding: 12px 14px; font-size: 12px; color: #64748b; font-style: italic;">No alerts in this category.</td></tr>'
    html_rows = []
    for ev in event_list:
        ts = html.escape(str(ev.get("timestamp", "")))
        mod = html.escape(str(ev.get("module", "")))
        msg = str(ev.get("message", ""))
        msg = html.escape(msg).replace("\n", "<br/>").replace("  ", "&nbsp;&nbsp;")
        
        row = f'''<tr>
          <td style="padding: 10px 14px; border-bottom: 1px solid {border_color}; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 11px; color: #64748b; white-space: nowrap; vertical-align: top;">{ts}</td>
          <td style="padding: 10px 14px; border-bottom: 1px solid {border_color}; vertical-align: top;"><span style="font-weight: 600; font-size: 11px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background-color: #f1f5f9; border: 1px solid #cbd5e1; padding: 2px 7px; border-radius: 4px; color: #1e293b; display: inline-block;">{mod}</span></td>
          <td style="padding: 10px 14px; border-bottom: 1px solid {border_color}; font-size: 12px; color: #0f172a; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.5; vertical-align: top;">{msg}</td>
        </tr>'''
        html_rows.append(row)
    return "\n".join(html_rows)

high_rows = build_rows(high_events, "#fee2e2")
medium_rows = build_rows(medium_events, "#fef3c7")
low_rows = build_rows(low_events[:10], "#e2e8f0")

if high_count > 0:
    banner_bg = "#fef2f2"
    banner_border = "#ef4444"
    banner_color = "#991b1b"
    banner_text = f"🚨 <strong>CRITICAL ATTENTION REQUIRED</strong>: High-severity security events detected on {html.escape(hostname)}"
elif medium_count >= 5:
    banner_bg = "#fffbeb"
    banner_border = "#f59e0b"
    banner_color = "#92400e"
    banner_text = f"⚠️ <strong>WARNING</strong>: Suspicious activity threshold exceeded on {html.escape(hostname)}"
else:
    banner_bg = "#f0fdf4"
    banner_border = "#10b981"
    banner_color = "#166534"
    banner_text = f"✅ <strong>ROUTINE MONITORING</strong>: All monitored host systems operating normally"

html_body = f'''From: HIDS Alert Service <{smtp_user}>
To: {email_to}
Subject: {subject}
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HIDS Security Report</title>
</head>
<body style="margin: 0; padding: 24px 12px; background-color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased; color: #1e293b;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width: 680px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05); border: 1px solid #cbd5e1;">
    
    <!-- HEADER -->
    <tr>
      <td style="background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); padding: 28px 32px; text-align: left;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
          <tr>
            <td>
              <h1 style="margin: 0; color: #ffffff; font-size: 22px; font-weight: 700; letter-spacing: -0.5px; line-height: 1.2;">
                <span style="font-size: 24px; vertical-align: middle; margin-right: 8px;">🛡️</span> HIDS Security Operations
              </h1>
              <p style="margin: 8px 0 0 0; color: #94a3b8; font-size: 13px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;">
                Host: <strong style="color: #f1f5f9;">{html.escape(hostname)}</strong> &nbsp;|&nbsp; Time: <strong style="color: #f1f5f9;">{html.escape(stamp)}</strong>
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>

    <!-- STATUS BANNER -->
    <tr>
      <td style="background-color: {banner_bg}; border-bottom: 2px solid {banner_border}; padding: 14px 32px; color: {banner_color}; font-size: 13px; line-height: 1.4;">
        {banner_text}
      </td>
    </tr>

    <!-- EXECUTIVE SUMMARY CARDS -->
    <tr>
      <td style="padding: 28px 32px 16px 32px;">
        <h2 style="margin: 0 0 16px 0; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: #64748b; font-weight: 700;">
          Executive Summary (Last {lines_count} Events)
        </h2>
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
          <tr>
            <td width="24%" style="padding-right: 6px;">
              <div style="background-color: #fef2f2; border-left: 4px solid #ef4444; border-radius: 6px; padding: 12px 14px; border: 1px solid #fee2e2;">
                <div style="font-size: 24px; font-weight: 800; color: #dc2626; line-height: 1;">{high_count}</div>
                <div style="font-size: 10px; font-weight: 700; color: #991b1b; text-transform: uppercase; margin-top: 6px; letter-spacing: 0.5px;">🔴 HIGH</div>
              </div>
            </td>
            <td width="24%" style="padding: 0 3px;">
              <div style="background-color: #fffbeb; border-left: 4px solid #f59e0b; border-radius: 6px; padding: 12px 14px; border: 1px solid #fef3c7;">
                <div style="font-size: 24px; font-weight: 800; color: #d97706; line-height: 1;">{medium_count}</div>
                <div style="font-size: 10px; font-weight: 700; color: #92400e; text-transform: uppercase; margin-top: 6px; letter-spacing: 0.5px;">🟠 MEDIUM</div>
              </div>
            </td>
            <td width="24%" style="padding: 0 3px;">
              <div style="background-color: #f0fdf4; border-left: 4px solid #10b981; border-radius: 6px; padding: 12px 14px; border: 1px solid #dcfce7;">
                <div style="font-size: 24px; font-weight: 800; color: #16a34a; line-height: 1;">{low_count}</div>
                <div style="font-size: 10px; font-weight: 700; color: #166534; text-transform: uppercase; margin-top: 6px; letter-spacing: 0.5px;">🟢 LOW</div>
              </div>
            </td>
            <td width="24%" style="padding-left: 6px;">
              <div style="background-color: #f8fafc; border-left: 4px solid #64748b; border-radius: 6px; padding: 12px 14px; border: 1px solid #e2e8f0;">
                <div style="font-size: 24px; font-weight: 800; color: #334155; line-height: 1;">{total_count}</div>
                <div style="font-size: 10px; font-weight: 700; color: #475569; text-transform: uppercase; margin-top: 6px; letter-spacing: 0.5px;">📊 TOTAL</div>
              </div>
            </td>
          </tr>
        </table>
      </td>
    </tr>

    <!-- HIGH ALERTS SECTION -->
    {'<tr><td style="padding: 12px 32px 20px 32px;"><div style="border-left: 4px solid #ef4444; padding-left: 10px; margin-bottom: 12px;"><h3 style="margin: 0; font-size: 14px; color: #991b1b; font-weight: 700;">Critical / High Severity Alerts (' + str(high_count) + ')</h3></div><table width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse: collapse; background-color: #ffffff; border: 1px solid #fee2e2; border-radius: 6px; overflow: hidden;"><thead><tr style="background-color: #fef2f2; text-align: left;"><th style="padding: 10px 14px; font-size: 11px; font-weight: 700; color: #991b1b; text-transform: uppercase; border-bottom: 1px solid #fee2e2;">Timestamp</th><th style="padding: 10px 14px; font-size: 11px; font-weight: 700; color: #991b1b; text-transform: uppercase; border-bottom: 1px solid #fee2e2;">Module</th><th style="padding: 10px 14px; font-size: 11px; font-weight: 700; color: #991b1b; text-transform: uppercase; border-bottom: 1px solid #fee2e2;">Message & Details</th></tr></thead><tbody>' + high_rows + '</tbody></table></td></tr>' if high_count > 0 else ''}

    <!-- MEDIUM ALERTS SECTION -->
    {'<tr><td style="padding: 12px 32px 20px 32px;"><div style="border-left: 4px solid #f59e0b; padding-left: 10px; margin-bottom: 12px;"><h3 style="margin: 0; font-size: 14px; color: #92400e; font-weight: 700;">Warning / Medium Severity Alerts (' + str(medium_count) + ')</h3></div><table width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse: collapse; background-color: #ffffff; border: 1px solid #fef3c7; border-radius: 6px; overflow: hidden;"><thead><tr style="background-color: #fffbeb; text-align: left;"><th style="padding: 10px 14px; font-size: 11px; font-weight: 700; color: #92400e; text-transform: uppercase; border-bottom: 1px solid #fef3c7;">Timestamp</th><th style="padding: 10px 14px; font-size: 11px; font-weight: 700; color: #92400e; text-transform: uppercase; border-bottom: 1px solid #fef3c7;">Module</th><th style="padding: 10px 14px; font-size: 11px; font-weight: 700; color: #92400e; text-transform: uppercase; border-bottom: 1px solid #fef3c7;">Message & Details</th></tr></thead><tbody>' + medium_rows + '</tbody></table></td></tr>' if medium_count > 0 else ''}

    <!-- LOW CHECKS SECTION -->
    <tr>
      <td style="padding: 12px 32px 28px 32px;">
        <div style="border-left: 4px solid #10b981; padding-left: 10px; margin-bottom: 12px;">
          <h3 style="margin: 0; font-size: 14px; color: #166534; font-weight: 700;">Routine / Low Severity Checks ({low_count})</h3>
        </div>
        <table width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse: collapse; background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; overflow: hidden;">
          <thead>
            <tr style="background-color: #f8fafc; text-align: left;">
              <th style="padding: 10px 14px; font-size: 11px; font-weight: 700; color: #475569; text-transform: uppercase; border-bottom: 1px solid #e2e8f0;">Timestamp</th>
              <th style="padding: 10px 14px; font-size: 11px; font-weight: 700; color: #475569; text-transform: uppercase; border-bottom: 1px solid #e2e8f0;">Module</th>
              <th style="padding: 10px 14px; font-size: 11px; font-weight: 700; color: #475569; text-transform: uppercase; border-bottom: 1px solid #e2e8f0;">Message & Details</th>
            </tr>
          </thead>
          <tbody>
            {low_rows}
          </tbody>
        </table>
      </td>
    </tr>

    <!-- FOOTER -->
    <tr>
      <td style="background-color: #f8fafc; border-top: 1px solid #e2e8f0; padding: 20px 32px; text-align: center;">
        <p style="margin: 0; font-size: 12px; color: #64748b;">
          Host-Based Intrusion Detection System (HIDS) &bull; Log: <code style="background: #e2e8f0; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-family: monospace;">{html.escape(log_file)}</code>
        </p>
        <p style="margin: 6px 0 0 0; font-size: 11px; color: #94a3b8;">
          Automated Security Report &bull; Generated at {html.escape(stamp)}
        </p>
      </td>
    </tr>

  </table>
</body>
</html>
'''

with open(payload_path, "w", encoding="utf-8") as f:
    f.write(html_body)
PYEOF

# If EMAIL_TO is not set, output report preview to stdout
if [ -z "${EMAIL_TO}" ]; then
  echo "EMAIL_TO is not configured. Displaying email report preview below:"
  echo ""
  cat "${PAYLOAD_FILE}"
  rm -f "${PAYLOAD_FILE}"
  exit 0
fi

# Send Email via curl SMTP or sendmail
echo "Sending HIDS report email to ${EMAIL_TO}..."

if command -v curl >/dev/null 2>&1 && [ -n "${SMTP_USER}" ] && [ -n "${SMTP_PASS}" ]; then
  if curl --ssl-reqd \
    --url "smtp://${SMTP_SERVER}" \
    --user "${SMTP_USER}:${SMTP_PASS}" \
    --mail-from "${SMTP_USER}" \
    --mail-rcpt "${EMAIL_TO}" \
    --upload-file "${PAYLOAD_FILE}" 2>/dev/null; then
    echo "Email report sent successfully via SMTP (${SMTP_SERVER})."
    rm -f "${PAYLOAD_FILE}"
    exit 0
  else
    echo "SMTP delivery failed with curl. Trying fallback mail command..." >&2
  fi
fi

if command -v sendmail >/dev/null 2>&1; then
  sendmail -t < "${PAYLOAD_FILE}"
  echo "Email report sent successfully via sendmail."
elif command -v mail >/dev/null 2>&1; then
  mail -s "${SUBJECT}" "${EMAIL_TO}" < "${PAYLOAD_FILE}"
  echo "Email report sent successfully via mail command."
else
  echo "ERROR: Could not send email. Ensure SMTP_USER & SMTP_PASS are set for curl, or install sendmail/mailx." >&2
  echo "Report payload saved at: ${PAYLOAD_FILE}"
  exit 1
fi

rm -f "${PAYLOAD_FILE}"
