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

# Determine how many lines to inspect (default: last 30 log entries)
LINES_COUNT="${1:-30}"

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

# Count alert severities
HIGH_COUNT=$(echo "${RECENT_EVENTS}" | grep -c '"severity":"HIGH"' || echo 0)
MEDIUM_COUNT=$(echo "${RECENT_EVENTS}" | grep -c '"severity":"MEDIUM"' || echo 0)
LOW_COUNT=$(echo "${RECENT_EVENTS}" | grep -c '"severity":"LOW"' || echo 0)
TOTAL_COUNT=$((HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT))

# Skip if EMAIL_ONLY_ON_ALERTS is true and no HIGH/MEDIUM alerts exist
if [ "${EMAIL_ONLY_ON_ALERTS}" = "true" ] && [ "${HIGH_COUNT}" -eq 0 ] && [ "${MEDIUM_COUNT}" -eq 0 ]; then
  echo "No HIGH or MEDIUM alerts found. Skipping email (EMAIL_ONLY_ON_ALERTS=true)."
  exit 0
fi

STAMP="$(date '+%Y-%m-%d %H:%M:%S %Z')"
SUBJECT="[HIDS Report] ${HOSTNAME_STR} Security Update - HIGH: ${HIGH_COUNT} | MEDIUM: ${MEDIUM_COUNT} | LOW: ${LOW_COUNT}"

# Extract formatted messages for each severity level
HIGH_ALERTS=$(echo "${RECENT_EVENTS}" | grep '"severity":"HIGH"' | awk -F'"message":"' '{print $2}' | sed 's/"}$//' | sed 's/\\n/\n    /g' || true)
MEDIUM_ALERTS=$(echo "${RECENT_EVENTS}" | grep '"severity":"MEDIUM"' | awk -F'"message":"' '{print $2}' | sed 's/"}$//' | sed 's/\\n/\n    /g' || true)
LOW_ALERTS=$(echo "${RECENT_EVENTS}" | grep '"severity":"LOW"' | awk -F'"message":"' '{print $2}' | sed 's/"}$//' | sed 's/\\n/\n    /g' || true)

# Build email payload file
PAYLOAD_FILE="$(mktemp)"

cat <<EOF > "${PAYLOAD_FILE}"
From: HIDS Alert Service <${SMTP_USER:-hids@${HOSTNAME_STR}}>
To: ${EMAIL_TO:-user@example.com}
Subject: ${SUBJECT}
Content-Type: text/plain; charset=UTF-8

===============================================================================
                    HIDS SECURITY MONITORING REPORT
===============================================================================
Host Name:     ${HOSTNAME_STR}
Report Time:   ${STAMP}
Log File:      ${LOG_FILE}

-------------------------------------------------------------------------------
1. ALERT SUMMARY (Last ${LINES_COUNT} Events)
-------------------------------------------------------------------------------
  Total Events Processed : ${TOTAL_COUNT}
  🔴 HIGH Severity        : ${HIGH_COUNT}
  🟠 MEDIUM Severity      : ${MEDIUM_COUNT}
  🟢 LOW Severity         : ${LOW_COUNT}

EOF

if [ "${HIGH_COUNT}" -gt 0 ]; then
cat <<EOF >> "${PAYLOAD_FILE}"
-------------------------------------------------------------------------------
2. CRITICAL / HIGH SEVERITY ALERTS (${HIGH_COUNT})
-------------------------------------------------------------------------------
EOF
  echo "${HIGH_ALERTS}" | while IFS= read -r line; do
    [ -n "${line}" ] && echo "  [CRITICAL] ${line}" >> "${PAYLOAD_FILE}"
  done
  echo "" >> "${PAYLOAD_FILE}"
fi

if [ "${MEDIUM_COUNT}" -gt 0 ]; then
cat <<EOF >> "${PAYLOAD_FILE}"
-------------------------------------------------------------------------------
3. WARNING / MEDIUM SEVERITY ALERTS (${MEDIUM_COUNT})
-------------------------------------------------------------------------------
EOF
  echo "${MEDIUM_ALERTS}" | while IFS= read -r line; do
    [ -n "${line}" ] && echo "  [WARNING] ${line}" >> "${PAYLOAD_FILE}"
  done
  echo "" >> "${PAYLOAD_FILE}"
fi

cat <<EOF >> "${PAYLOAD_FILE}"
-------------------------------------------------------------------------------
4. ROUTINE / LOW SEVERITY CHECKS (${LOW_COUNT})
-------------------------------------------------------------------------------
EOF
if [ "${LOW_COUNT}" -gt 0 ]; then
  echo "${LOW_ALERTS}" | head -n 10 | while IFS= read -r line; do
    [ -n "${line}" ] && echo "  [INFO] ${line}" >> "${PAYLOAD_FILE}"
  done
else
  echo "  No low severity events in recent window." >> "${PAYLOAD_FILE}"
fi

cat <<EOF >> "${PAYLOAD_FILE}"

===============================================================================
End of HIDS Report.
===============================================================================
EOF

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
