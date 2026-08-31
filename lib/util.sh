#!/usr/bin/env bash
set -uo pipefail

# Returns 0 if stdout is an interactive terminal, 1 otherwise.
is_tty() {
  if [ -t 1 ]; then
    return 0
  fi
  return 1
}

# Collapses newlines, carriage returns and tabs into single spaces, squeezes runs.
flatten() {
  local s
  if [ "$#" -gt 0 ]; then
    s="$1"
  else
    s="$(cat -)"
  fi
  # Translate CR, LF and TAB to spaces, squeeze runs of whitespace, trim ends.
  printf '%s' "$s" | tr '\r\n\t' '   ' | sed -E 's/[[:space:]]+/ /g' | sed -E 's/^ //; s/ $//'
}

# Escapes backslashes and double quotes for safe embedding in a JSON string.
json_escape() {
  local s
  if [ "$#" -gt 0 ]; then
    s="$1"
  else
    s="$(cat -)"
  fi
  # Escape backslashes first, then double quotes.
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '%s' "$s"
}

# Prints text in the given colour when stdout is a TTY, plain otherwise.
# Colours: INFO=default LOW=cyan MEDIUM=yellow HIGH=red CRITICAL=bold-red-reverse
colourise() {
  local sev="${1:-INFO}"
  shift || true
  local text="$*"
  local reset='\033[0m'
  local cyan='\033[36m'
  local yellow='\033[33m'
  local red='\033[31m'
  local bold_red_reverse='\033[1;7;31m'

  if is_tty; then
    case "${sev^^}" in
      INFO)
        printf '%s\n' "$text"
        ;;
      LOW)
        printf '%b\n' "${cyan}${text}${reset}"
        ;;
      MEDIUM)
        printf '%b\n' "${yellow}${text}${reset}"
        ;;
      HIGH)
        printf '%b\n' "${red}${text}${reset}"
        ;;
      CRITICAL)
        printf '%b\n' "${bold_red_reverse}${text}${reset}"
        ;;
      *)
        printf '%s\n' "$text"
        ;;
    esac
  else
    printf '%s\n' "$text"
  fi
}
