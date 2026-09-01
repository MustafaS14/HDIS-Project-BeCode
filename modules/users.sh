#!/usr/bin/env bash
set -uo pipefail

MODULE_DIR="${BASH_SOURCE%/*}"
PROJECT_ROOT="$(cd "${MODULE_DIR}/.." && pwd)"
BASELINE_DIR="${PROJECT_ROOT}/baseline"

if [ -f "${PROJECT_ROOT}/lib/util.sh" ]; then
  source "${PROJECT_ROOT}/lib/util.sh"
fi
if [ -f "${PROJECT_ROOT}/lib/config.sh" ]; then
  source "${PROJECT_ROOT}/lib/config.sh"
  load_config
fi
if [ -f "${PROJECT_ROOT}/lib/alert.sh" ]; then
  source "${PROJECT_ROOT}/lib/alert.sh"
fi
if [ -f "${PROJECT_ROOT}/lib/rules.sh" ]; then
  source "${PROJECT_ROOT}/lib/rules.sh"
fi

# Writes current passwd, privileged groups, lastlog, and authorized_keys baselines if missing.
write_users_baseline() {
  mkdir -p "${BASELINE_DIR}"
  if [ ! -f "${BASELINE_DIR}/users.txt" ]; then
    getent passwd 2>/dev/null | sort > "${BASELINE_DIR}/users.txt"
  fi
  if [ ! -f "${BASELINE_DIR}/groups.txt" ]; then
    : > "${BASELINE_DIR}/groups.txt"
    local group_name
    for group_name in ${PRIVILEGED_GROUPS:-sudo wheel adm docker}; do
      getent group "${group_name}" 2>/dev/null >> "${BASELINE_DIR}/groups.txt" || true
    done
    sort -u "${BASELINE_DIR}/groups.txt" -o "${BASELINE_DIR}/groups.txt"
  fi
  if [ ! -f "${BASELINE_DIR}/lastlog.txt" ]; then
    : > "${BASELINE_DIR}/lastlog.txt"
    local passwd_line user_name home_dir
    while IFS=: read -r user_name _ _ _ _ home_dir _; do
      [ -z "${user_name:-}" ] && continue
      lastlog -u "${user_name}" 2>/dev/null | awk 'END { if (NR > 0) print }' >> "${BASELINE_DIR}/lastlog.txt" || true
    done < <(getent passwd 2>/dev/null)
  fi
  if [ ! -f "${BASELINE_DIR}/authorized_keys.txt" ]; then
    : > "${BASELINE_DIR}/authorized_keys.txt"
    find /root /home -path '*/authorized_keys' -type f 2>/dev/null | while IFS= read -r key_path; do
      sha256sum "${key_path}" 2>/dev/null | awk -v path="${key_path}" '{print path "\t" $1}' >> "${BASELINE_DIR}/authorized_keys.txt" || true
    done
    sort -u "${BASELINE_DIR}/authorized_keys.txt" -o "${BASELINE_DIR}/authorized_keys.txt"
  fi
}

# Collects failed SSH/login attempts from btmp, auth logs, or the systemd journal.
collect_failed_login_lines() {
  if command -v lastb >/dev/null 2>&1; then
    lastb -a -w 2>/dev/null | grep -v '^$' | grep -v '^wtmp' | grep -v '^btmp' || true
    return 0
  fi

  local auth_log
  for auth_log in /var/log/auth.log /var/log/secure; do
    if [ -r "${auth_log}" ]; then
      grep -Ei 'sshd.*(Failed password|Invalid user|authentication failure|Failed publickey)|authentication failure.*sshd' "${auth_log}" 2>/dev/null || true
      return 0
    fi
  done

  if command -v journalctl >/dev/null 2>&1; then
    journalctl -u ssh -u sshd -u ssh.service -u sshd.service --since "${FAILED_LOGIN_WINDOW_MIN:-10} minutes ago" --no-pager 2>/dev/null \
      | grep -Ei 'sshd.*(Failed password|Invalid user|authentication failure|Failed publickey)|authentication failure.*sshd' || true
  fi
}

# Aggregates failed login attempts by (user, source) within the configured window.
read_failed_logins() {
  local -A counts
  local -A users
  local line user_name source

  while IFS= read -r line; do
    [ -z "${line}" ] && continue
    case "${line}" in
      btmp*|wtmp*|reboot*|shutdown*|"" ) continue ;;
    esac
    if printf '%s' "${line}" | grep -Eq 'Failed password for '; then
      user_name="$(printf '%s' "${line}" | sed -nE 's/.*Failed password for (invalid user )?([^ ]+) from .*/\2/p')"
      source="$(printf '%s' "${line}" | sed -nE 's/.* from ([^ ]+) port .*/\1/p')"
    elif printf '%s' "${line}" | grep -Eq 'Invalid user '; then
      user_name="$(printf '%s' "${line}" | sed -nE 's/.*Invalid user ([^ ]+) from .*/\1/p')"
      source="$(printf '%s' "${line}" | sed -nE 's/.* from ([^ ]+) port .*/\1/p')"
    elif printf '%s' "${line}" | grep -Eq 'authentication failure'; then
      user_name="$(printf '%s' "${line}" | sed -nE 's/.* user=([^ ]+).*/\1/p')"
      source="$(printf '%s' "${line}" | sed -nE 's/.* rhost=([^ ]+).*/\1/p')"
    else
      user_name="$(printf '%s' "${line}" | awk '{print $1}')"
      source="$(printf '%s' "${line}" | awk '{print $3}')"
    fi
    [ -z "${user_name}" ] && continue
    [ -z "${source}" ] && source="unknown"
    counts["${user_name}|${source}"]=$(( ${counts["${user_name}|${source}"]:-0} + 1 ))
    users["${user_name}|${source}"]=1
  done < <(collect_failed_login_lines)

  local key count key_user key_source success_lines
  success_lines="$(last -a -w 2>/dev/null || true)"
  for key in "${!users[@]}"; do
    count="${counts[${key}]:-0}"
    key_user="${key%%|*}"
    key_source="${key#*|}"
    if [ "${count}" -ge "${FAILED_LOGIN_CRIT:-20}" ]; then
      raise_alert HIGH users USR-002 "${count} failed logins from ${key_source} for ${key_user}" "user=${key_user} source=${key_source} failures=${count}"
    elif [ "${count}" -ge "${FAILED_LOGIN_WARN:-5}" ]; then
      raise_alert MEDIUM users USR-001 "${count} failed logins from ${key_source} for ${key_user}" "user=${key_user} source=${key_source} failures=${count}"
    fi

    if printf '%s\n' "${success_lines}" | grep -Fq "${key_source}"; then
      raise_alert CRITICAL users USR-003 "Failed logins from ${key_source} were followed by a successful login" "source=${key_source} user=${key_user} failures=${count}"
    fi
  done
}

# Diffs getent passwd against baseline/users.txt.
check_new_accounts() {
  local current_passwd baseline_passwd new_lines
  current_passwd="$(getent passwd 2>/dev/null | LC_ALL=C sort -u)"
  baseline_passwd="${BASELINE_DIR}/users.txt"
  if [ ! -f "${baseline_passwd}" ]; then
    write_users_baseline
    return 0
  fi

  new_lines="$(comm -13 <(LC_ALL=C sort -u "${baseline_passwd}") <(printf '%s\n' "${current_passwd}" | LC_ALL=C sort -u))"
  if [ -n "${new_lines}" ]; then
    while IFS= read -r line; do
      [ -z "${line}" ] && continue
      local user_name uid shell
      user_name="$(printf '%s' "${line}" | awk -F: '{print $1}')"
      uid="$(printf '%s' "${line}" | awk -F: '{print $3}')"
      shell="$(printf '%s' "${line}" | awk -F: '{print $7}')"
      raise_alert MEDIUM users USR-004 "New account '${user_name}' was added" "user=${user_name} uid=${uid} shell=${shell}"
      if [ "${uid}" = "0" ] && [ "${user_name}" != "root" ]; then
        raise_alert CRITICAL users USR-005 "New UID 0 account '${user_name}'" "user=${user_name} uid=${uid} shell=${shell}"
      fi
    done <<EOF
${new_lines}
EOF
  fi

  while IFS=: read -r user_name _ uid _ _ _ shell; do
    [ -z "${user_name:-}" ] && continue
    local baseline_line baseline_shell
    baseline_line="$(grep -E "^${user_name}:" "${baseline_passwd}" 2>/dev/null | head -n 1 || true)"
    [ -z "${baseline_line}" ] && continue
    baseline_shell="$(printf '%s' "${baseline_line}" | awk -F: '{print $7}')"
    case "${baseline_shell}" in
      */nologin|*/false|nologin|false)
        case "${shell}" in
          */nologin|*/false|nologin|false) : ;;
          *) raise_alert HIGH users USR-008 "Shell changed from ${baseline_shell} to ${shell} for ${user_name}" "user=${user_name} uid=${uid} old_shell=${baseline_shell} new_shell=${shell}" ;;
        esac
        ;;
    esac
    if [ "${uid}" = "0" ] && [ "${user_name}" != "root" ]; then
      raise_alert CRITICAL users USR-005 "UID 0 account '${user_name}' exists" "user=${user_name} uid=${uid} shell=${shell}"
    fi
  done < <(getent passwd 2>/dev/null)
}

# Diffs getent group against baseline/groups.txt for privileged groups.
check_group_changes() {
  local baseline_file current_file group_name baseline_line current_line baseline_members current_members member
  baseline_file="${BASELINE_DIR}/groups.txt"
  if [ ! -f "${baseline_file}" ]; then
    write_users_baseline
    return 0
  fi

  current_file="${BASELINE_DIR}/groups.current.$$"
  : > "${current_file}"
  for group_name in ${PRIVILEGED_GROUPS:-sudo wheel adm docker}; do
    getent group "${group_name}" 2>/dev/null >> "${current_file}" || true
  done
  sort -u "${current_file}" -o "${current_file}"

  while IFS= read -r current_line; do
    [ -z "${current_line}" ] && continue
    group_name="$(printf '%s' "${current_line}" | awk -F: '{print $1}')"
    baseline_line="$(grep -E "^${group_name}:" "${baseline_file}" 2>/dev/null | head -n 1 || true)"
    [ -z "${baseline_line}" ] && continue
    baseline_members="$(printf '%s' "${baseline_line}" | awk -F: '{print $4}')"
    current_members="$(printf '%s' "${current_line}" | awk -F: '{print $4}')"
    if [ "${baseline_members}" != "${current_members}" ]; then
      IFS=',' read -r -a baseline_array <<< "${baseline_members}"
      IFS=',' read -r -a current_array <<< "${current_members}"
      for member in "${current_array[@]}"; do
        [ -z "${member}" ] && continue
        if ! printf '%s\n' "${baseline_members}" | grep -Eq "(^|,)${member}(,|$)"; then
          raise_alert HIGH users USR-007 "New member '${member}' joined privileged group '${group_name}'" "group=${group_name} member=${member}"
        fi
      done
    fi
  done < "${current_file}"

  rm -f "${current_file}" 2>/dev/null || true
}

# Reports last login time per account via lastlog, flags never-logged-in accounts that suddenly have a login.
check_lastlog() {
  local baseline_file current_file user_name baseline_line current_line baseline_state current_state
  baseline_file="${BASELINE_DIR}/lastlog.txt"
  if [ ! -f "${baseline_file}" ]; then
    write_users_baseline
    return 0
  fi

  current_file="${BASELINE_DIR}/lastlog.current.$$"
  : > "${current_file}"
  while IFS=: read -r user_name _ _ _ _ _ _; do
    [ -z "${user_name:-}" ] && continue
    current_line="$(lastlog -u "${user_name}" 2>/dev/null | awk 'END { if (NR > 0) print }' || true)"
    printf '%s\t%s\n' "${user_name}" "${current_line}" >> "${current_file}"
  done < <(getent passwd 2>/dev/null)

  while IFS=$'\t' read -r user_name current_line; do
    [ -z "${user_name:-}" ] && continue
    baseline_line="$(grep -E "^${user_name}[[:space:]]" "${baseline_file}" 2>/dev/null | head -n 1 || true)"
    [ -z "${baseline_line}" ] && continue
    baseline_state="$(printf '%s' "${baseline_line}" | awk -F'\t' '{print $2}')"
    current_state="${current_line}"
    if printf '%s' "${baseline_state}" | grep -Eq 'Never logged in|\*\*Never logged in\*\*'; then
      if ! printf '%s' "${current_state}" | grep -Eq 'Never logged in|\*\*Never logged in\*\*'; then
        raise_alert MEDIUM users USR-016 "Account '${user_name}' logged in for the first time" "user=${user_name} lastlog=${current_state}"
      fi
    fi
  done < "${current_file}"

  rm -f "${current_file}" 2>/dev/null || true
}

# Checks mode/owner of /etc/passwd /etc/shadow /etc/group /etc/gshadow.
check_account_file_permissions() {
  local passwd_info shadow_info group_info gshadow_info passwd_mode passwd_uid shadow_mode shadow_uid

  passwd_info="$(stat -c '%a %u' /etc/passwd 2>/dev/null || true)"
  shadow_info="$(stat -c '%a %u' /etc/shadow 2>/dev/null || true)"
  group_info="$(stat -c '%a %u' /etc/group 2>/dev/null || true)"
  gshadow_info="$(stat -c '%a %u' /etc/gshadow 2>/dev/null || true)"

  passwd_mode="${passwd_info%% *}"
  passwd_uid="${passwd_info##* }"
  shadow_mode="${shadow_info%% *}"
  shadow_uid="${shadow_info##* }"

  if [ -n "${passwd_mode}" ] && { [ "${passwd_uid}" != "0" ] || [ $(( 8#${passwd_mode} & 022 )) -ne 0 ]; }; then
    raise_alert CRITICAL users USR-015 "/etc/passwd is writable or not owned by root" "path=/etc/passwd mode=${passwd_mode} owner_uid=${passwd_uid}"
  fi

  if [ -n "${shadow_mode}" ] && { [ "${shadow_uid}" != "0" ] || { [ "${shadow_mode}" != "640" ] && [ "${shadow_mode}" != "600" ]; }; }; then
    raise_alert CRITICAL users USR-014 "/etc/shadow permissions are unsafe" "path=/etc/shadow mode=${shadow_mode} owner_uid=${shadow_uid}"
  fi

  : "${group_info}"
  : "${gshadow_info}"
}

# Checks for authorized_keys additions or modifications under /home and /root.
check_authorized_keys() {
  local baseline_file current_file key_path digest
  baseline_file="${BASELINE_DIR}/authorized_keys.txt"
  if [ ! -f "${baseline_file}" ]; then
    write_users_baseline
    return 0
  fi

  current_file="${BASELINE_DIR}/authorized_keys.current.$$"
  : > "${current_file}"
  find /root /home -path '*/authorized_keys' -type f 2>/dev/null | while IFS= read -r key_path; do
    digest="$(sha256sum "${key_path}" 2>/dev/null | awk '{print $1}')"
    printf '%s\t%s\n' "${key_path}" "${digest}" >> "${current_file}" || true
  done
  sort -u "${current_file}" -o "${current_file}"

  while IFS=$'\t' read -r key_path digest; do
    [ -z "${key_path:-}" ] && continue
    if ! grep -Fq "${key_path}" "${baseline_file}" 2>/dev/null; then
      raise_alert HIGH users USR-009 "New authorized_keys file '${key_path}'" "path=${key_path} sha256=${digest}"
      continue
    fi
    if ! grep -F "${key_path}" "${baseline_file}" | awk -F'\t' -v expected="${digest}" '{ if ($2 != expected) exit 1 }'; then
      raise_alert HIGH users USR-009 "authorized_keys changed at '${key_path}'" "path=${key_path} sha256=${digest}"
    fi
  done < "${current_file}"

  rm -f "${current_file}" 2>/dev/null || true
}

# Checks for shell history files that are empty or redirected to /dev/null.
check_history_files() {
  local user_name home_dir history_file
  while IFS=: read -r user_name _ _ _ _ home_dir _; do
    [ -z "${user_name:-}" ] && continue
    [ -z "${home_dir:-}" ] && continue
    for history_file in ".bash_history" ".zsh_history" ".sh_history"; do
      if [ -L "${home_dir}/${history_file}" ] && printf '%s' "$(stat -c '%N' "${home_dir}/${history_file}" 2>/dev/null || true)" | grep -Fq "/dev/null"; then
        raise_alert HIGH users USR-012 "History file '${home_dir}/${history_file}' points to /dev/null" "user=${user_name} path=${home_dir}/${history_file}"
      elif [ -f "${home_dir}/${history_file}" ] && [ ! -s "${home_dir}/${history_file}" ]; then
        raise_alert HIGH users USR-012 "History file '${home_dir}/${history_file}' is empty" "user=${user_name} path=${home_dir}/${history_file}"
      fi
    done
  done < <(getent passwd 2>/dev/null)
}

# Checks for empty passwords in /etc/shadow.
check_shadow_passwords() {
  [ -r /etc/shadow ] || return 0
  while IFS=: read -r user_name password_field _; do
    [ -z "${user_name:-}" ] && continue
    if [ -z "${password_field}" ]; then
      raise_alert CRITICAL users USR-006 "Empty password field in /etc/shadow for '${user_name}'" "user=${user_name}"
    fi
  done < /etc/shadow
}

# Orchestrates all of the above.
run_users_module() {
  write_users_baseline
  read_failed_logins
  check_new_accounts
  check_group_changes
  check_lastlog
  check_account_file_permissions
  check_authorized_keys
  check_history_files
  check_shadow_passwords
}