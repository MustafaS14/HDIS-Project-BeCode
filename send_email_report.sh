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

# Extract recent log entries (rolling window shown in the email body/summary for both modes)
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

if [ "${REPORT_MODE}" = "instant" ]; then
  # Send a fresh instant email for every new HIGH/MEDIUM event since the last check, tracked by
  # log line offset rather than content hashing, so distinct repeated incidents (e.g. running the
  # same recon command again) are never silently suppressed as "duplicates".
  mkdir -p "${STATE_DIR}"
  OFFSET_FILE="${STATE_DIR}/instant_email.offset"
  TOTAL_LINES="$(wc -l < "${LOG_FILE}" 2>/dev/null || echo 0)"
  LAST_OFFSET=0
  if [ -f "${OFFSET_FILE}" ]; then
    LAST_OFFSET="$(cat "${OFFSET_FILE}" 2>/dev/null || echo 0)"
  fi
  if ! [[ "${LAST_OFFSET}" =~ ^[0-9]+$ ]] || [ "${LAST_OFFSET}" -gt "${TOTAL_LINES}" ]; then
    LAST_OFFSET=0
  fi

  NEW_EVENTS=""
  if [ "${TOTAL_LINES}" -gt "${LAST_OFFSET}" ]; then
    NEW_EVENTS="$(tail -n +"$((LAST_OFFSET + 1))" "${LOG_FILE}" 2>/dev/null || true)"
  fi
  # Mark all current lines as seen so each event is only ever considered once, regardless of
  # whether this run ends up sending an email.
  echo "${TOTAL_LINES}" > "${OFFSET_FILE}"

  NEW_HIGH_COUNT=$(printf '%s\n' "${NEW_EVENTS}" | grep -c '"severity":"HIGH"' 2>/dev/null || true)
  NEW_MEDIUM_COUNT=$(printf '%s\n' "${NEW_EVENTS}" | grep -c '"severity":"MEDIUM"' 2>/dev/null || true)
  NEW_HIGH_COUNT=$(echo "${NEW_HIGH_COUNT}" | tr -d '[:space:]')
  NEW_MEDIUM_COUNT=$(echo "${NEW_MEDIUM_COUNT}" | tr -d '[:space:]')
  NEW_HIGH_COUNT=${NEW_HIGH_COUNT:-0}
  NEW_MEDIUM_COUNT=${NEW_MEDIUM_COUNT:-0}

  if [ "${NEW_HIGH_COUNT}" -lt 1 ] && [ "${NEW_MEDIUM_COUNT}" -lt 5 ]; then
    echo "No new HIGH/MEDIUM events since the last check (Requires HIGH >= 1 or MEDIUM >= 5 among new events; new HIGH: ${NEW_HIGH_COUNT}, new MEDIUM: ${NEW_MEDIUM_COUNT}). Skipping instant email."
    exit 0
  fi

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

# Group events by functional module category rather than severity.
MODULE_CATEGORIES = [
    ("System Health", "#0ea5e9", ["system_health", "summary", "scheduler", "elk_ship"]),
    ("User Activity", "#8b5cf6", ["user_activity", "user_monitor", "privilege_monitor", "brute_force"]),
    ("Process & Network Audit", "#f97316", ["process_network", "process_monitor", "network_monitor", "unusual_ports", "beaconing"]),
    ("File Integrity", "#14b8a6", ["file_integrity", "baseline", "demo"]),
]
MODULE_TO_CATEGORY = {mod: name for name, _color, mods in MODULE_CATEGORIES for mod in mods}
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "WARNING": 1, "LOW": 2}

categorized = {name: [] for name, _color, _mods in MODULE_CATEGORIES}
categorized["Other"] = []
for ev in events:
    category = MODULE_TO_CATEGORY.get(ev.get("module", ""), "Other")
    categorized[category].append(ev)
for name in categorized:
    categorized[name].sort(key=lambda e: SEVERITY_ORDER.get(e.get("severity", "LOW"), 2))

SEVERITY_BADGE_STYLE = {
    "HIGH": ("#fee2e2", "#991b1b", "🔴 HIGH"),
    "MEDIUM": ("#fef3c7", "#92400e", "🟠 MEDIUM"),
    "WARNING": ("#fef3c7", "#92400e", "🟠 WARNING"),
    "LOW": ("#dcfce7", "#166534", "🟢 LOW"),
}

# Plain-English translations of raw log messages, keyed by module then a substring match.
FRIENDLY_RULES = {
    "system_health": [
        ("exceeded thresholds", "Multiple system health metrics (CPU, memory, disk, network, etc.) are outside normal range — this computer may be under strain."),
        ("all monitored health metrics within normal range", "This computer's health metrics (CPU, memory, disk, network, etc.) all look normal."),
    ],
    "user_activity": [
        ("Reconnaissance command activity detected", "Someone ran commands typically used to explore a system after gaining access (like whoami, id, or scanning for privileged files) — this can indicate an intruder is investigating the machine."),
        ("Frequent sudo/su usage by non-admin", "A non-administrator account has been repeatedly using elevated (sudo/su) commands — this could mean an account is being abused to gain more access."),
        ("Persistence tampering detected", "A scheduled task (cron) or SSH access file was added or changed — attackers commonly do this to maintain access to a system."),
        ("Command history appears to have been cleared", "A user's command history was unexpectedly cleared or shortened — this is a common way attackers try to hide their tracks."),
        ("Process masquerading as a system service detected", "A program is pretending to be a legitimate system service but is running from an unusual location — a common malware disguise technique."),
        ("No insider-threat indicators detected", "No signs of insider threats or post-compromise behavior (recon commands, privilege abuse, tampering, or disguised processes) were found."),
        ("Recent failed login attempts", "Multiple failed login attempts were recorded recently — someone may be trying to guess a password."),
        ("No users are currently logged in", "No one is currently logged into this computer."),
        ("Current active sessions", "One or more users are currently logged into this computer."),
        ("No recent login history available", "No recent login activity was found."),
        ("Recent login activity", "Recent successful logins were recorded on this computer."),
    ],
    "process_network": [
        ("Suspicious running processes detected", "One or more potentially risky programs are currently running."),
        ("No obviously suspicious processes detected", "No unusual or risky programs were found running."),
        ("No network listeners identified", "No open network connections were found."),
        ("Current listeners", "This computer has open network connections, which is expected for normal operation."),
    ],
    "process_monitor": [
        ("Unexpected new processes detected", "New programs started running that were not seen before — worth a quick check."),
        ("No unexpected process activity detected", "No new or unusual programs were found running."),
    ],
    "network_monitor": [
        ("Unexpected network listener detected", "A new network connection appeared that wasn't there before — this could mean unauthorized access."),
        ("No unexpected network listeners detected", "No new network services were found."),
    ],
    "file_integrity": [
        ("Critical file missing", "A critical system file is missing — this may indicate tampering or accidental deletion."),
        ("Integrity change detected", "An important system file was changed unexpectedly — please verify this was intentional."),
        ("No file integrity issues detected", "All critical system files are unchanged and appear intact."),
    ],
    "user_monitor": [
        ("New user or account change detected", "A user account was added or changed — please confirm this was expected."),
        ("No new user accounts detected", "No new user accounts were created."),
    ],
    "privilege_monitor": [
        ("New privileged binary detected", "A new program with admin-level permissions was found — this needs immediate review."),
        ("No new privileged binaries detected", "No new high-permission programs were found."),
    ],
    "unusual_ports": [
        ("", "Network activity was detected on an unusual port, which can be a sign of hidden or unauthorized software."),
    ],
    "beaconing": [
        ("", "Repeated, regularly-timed connections to the same address were detected — a common sign of malware secretly \"phoning home\" to an attacker."),
    ],
    "brute_force": [
        ("", "Multiple failed logins followed by a successful one were detected — a strong sign of a password-guessing attack."),
    ],
    "summary": [
        ("", "A routine summary report was generated."),
    ],
    "scheduler": [
        ("could not be configured", "Automatic monitoring could not be scheduled — manual setup may be required."),
        ("", "Automatic monitoring schedule was set up successfully."),
    ],
    "elk_ship": [
        ("failed", "There was a problem sending security data to the dashboard."),
        ("not found", "There was a problem sending security data to the dashboard."),
        ("", "Security data was sent to the dashboard successfully."),
    ],
    "demo": [
        ("", "A simulated test incident was triggered for demonstration purposes."),
    ],
    "baseline": [
        ("", "A reference snapshot of system files was created for future comparisons."),
    ],
}

FALLBACK_BY_SEVERITY = {
    "HIGH": "A high-severity security event was detected — review the details below.",
    "MEDIUM": "A potential issue was detected that may need attention.",
    "WARNING": "A potential issue was detected that may need attention.",
    "LOW": "Routine check completed with no issues found.",
}

def friendly_summary(module, severity, message):
    for needle, plain_text in FRIENDLY_RULES.get(module, []):
        if needle == "" or needle in message:
            return plain_text
    return FALLBACK_BY_SEVERITY.get(severity, "A security event was recorded — see details below.")

def build_rows(event_list, border_color="#e2e8f0"):
    if not event_list:
        return f'<tr><td colspan="4" style="padding: 12px 14px; font-size: 12px; color: #64748b; font-style: italic;">No alerts in this category.</td></tr>'
    html_rows = []
    for ev in event_list:
        ts = html.escape(str(ev.get("timestamp", "")))
        mod_raw = str(ev.get("module", ""))
        mod = html.escape(mod_raw)
        raw_message = str(ev.get("message", ""))
        plain_text = html.escape(friendly_summary(mod_raw, ev.get("severity", "LOW"), raw_message))
        msg = html.escape(raw_message).replace("\n", "<br/>").replace("  ", "&nbsp;&nbsp;")
        sev_bg, sev_color, sev_label = SEVERITY_BADGE_STYLE.get(ev.get("severity", "LOW"), SEVERITY_BADGE_STYLE["LOW"])

        row = f'''<tr>
          <td style="padding: 10px 14px; border-bottom: 1px solid {border_color}; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 11px; color: #64748b; white-space: nowrap; vertical-align: top;">{ts}</td>
          <td style="padding: 10px 14px; border-bottom: 1px solid {border_color}; vertical-align: top; white-space: nowrap;"><span style="font-weight: 700; font-size: 10px; background-color: {sev_bg}; color: {sev_color}; padding: 2px 7px; border-radius: 4px; display: inline-block;">{sev_label}</span></td>
          <td style="padding: 10px 14px; border-bottom: 1px solid {border_color}; vertical-align: top;"><span style="font-weight: 600; font-size: 11px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background-color: #f1f5f9; border: 1px solid #cbd5e1; padding: 2px 7px; border-radius: 4px; color: #1e293b; display: inline-block;">{mod}</span></td>
          <td style="padding: 10px 14px; border-bottom: 1px solid {border_color}; font-size: 12px; color: #0f172a; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.5; vertical-align: top;">
            <div style="font-weight: 600;">{plain_text}</div>
            <div style="margin-top: 4px; font-size: 11px; color: #64748b; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;">Details: {msg}</div>
          </td>
        </tr>'''
        html_rows.append(row)
    return "\n".join(html_rows)

def build_category_section(name, accent_color, event_list):
    if not event_list:
        return ""
    rows = build_rows(event_list, "#e2e8f0")
    return f'''<tr><td style="padding: 12px 32px 20px 32px;">
      <div style="border-left: 4px solid {accent_color}; padding-left: 10px; margin-bottom: 12px;">
        <h3 style="margin: 0; font-size: 14px; color: #1e293b; font-weight: 700;">{html.escape(name)} ({len(event_list)})</h3>
      </div>
      <table width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse: collapse; background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; overflow: hidden;">
        <thead><tr style="background-color: #f8fafc; text-align: left;">
          <th style="padding: 10px 14px; font-size: 11px; font-weight: 700; color: #475569; text-transform: uppercase; border-bottom: 1px solid #e2e8f0;">Timestamp</th>
          <th style="padding: 10px 14px; font-size: 11px; font-weight: 700; color: #475569; text-transform: uppercase; border-bottom: 1px solid #e2e8f0;">Severity</th>
          <th style="padding: 10px 14px; font-size: 11px; font-weight: 700; color: #475569; text-transform: uppercase; border-bottom: 1px solid #e2e8f0;">Module</th>
          <th style="padding: 10px 14px; font-size: 11px; font-weight: 700; color: #475569; text-transform: uppercase; border-bottom: 1px solid #e2e8f0;">What Happened</th>
        </tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </td></tr>'''

category_sections = "\n".join(
    build_category_section(name, color, categorized[name]) for name, color, _mods in MODULE_CATEGORIES
) + build_category_section("Other", "#64748b", categorized["Other"])

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

    <!-- MODULE CATEGORY SECTIONS -->
    {category_sections}

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
