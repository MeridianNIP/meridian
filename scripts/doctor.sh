#!/usr/bin/env bash
# =====================================================================
# Meridian · doctor
# =====================================================================
# Friendly wrapper around `meridian-nip doctor` + environment checks that
# do not require the app venv. Safe to run any time; changes nothing.
# =====================================================================

set -uo pipefail

C_RESET=$'\e[0m'; C_BOLD=$'\e[1m'; C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'; C_RED=$'\e[31m'; C_DIM=$'\e[2m'
FAIL=0

section() { printf '\n%s── %s ──%s\n' "$C_BOLD" "$1" "$C_RESET"; }
pass()    { printf "  %s✓%s %s %s%s%s\n" "$C_GREEN" "$C_RESET" "$1" "$C_DIM" "${2:-}" "$C_RESET"; }
warn()    { printf "  %s!%s %s  %s\n" "$C_YELLOW" "$C_RESET" "$1" "${2:-}"; }
fail()    { printf "  %s✗%s %s  %s\n" "$C_RED"    "$C_RESET" "$1" "${2:-}"; FAIL=1; }

section "Environment"
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  if [[ "$ID" == "debian" ]] && [[ "$VERSION_ID" =~ ^(12|13)$ ]]; then
    pass "OS" "$PRETTY_NAME"
  else
    warn "OS" "$PRETTY_NAME — supported: Debian 12 (bookworm) or 13 (trixie)"
  fi
fi
pass "kernel" "$(uname -r)"
pass "arch"   "$(dpkg --print-architecture 2>/dev/null || uname -m)"

section "Paths"
for p in /opt/meridian /etc/meridian /var/lib/meridian /var/log/meridian; do
  [[ -d "$p" ]] && pass "$p" "present" || fail "$p" "missing"
done

section "Key material"
for key in /etc/meridian/secrets/master.key /etc/meridian/secrets/row_hmac.key; do
  if [[ -r "$key" ]]; then
    mode=$(stat -c '%a' "$key")
    [[ "$mode" == "400" ]] && pass "$key" "0400" || warn "$key" "perms=$mode (want 0400)"
  else
    fail "$key" "unreadable"
  fi
done

section "App doctor"
if [[ -x /opt/meridian/venv/bin/python ]]; then
  /opt/meridian/venv/bin/python -m app.cli doctor || FAIL=1
else
  fail "venv" "/opt/meridian/venv/bin/python missing"
fi

section "Recent log errors (last hour)"
ERRORS=0
for log in /var/log/meridian/*.log; do
  [[ -r "$log" ]] || continue
  n=$(awk -v cutoff="$(date -u -d '1 hour ago' '+%Y-%m-%dT%H:%M:%S')" \
      '$0 > cutoff && tolower($0) ~ /error|traceback|critical/' "$log" | wc -l)
  (( n )) && warn "$(basename "$log")" "$n error lines" && ERRORS=$((ERRORS+n))
done
(( ERRORS == 0 )) && pass "app logs" "clean"

echo
if (( FAIL )); then
  printf '%sdoctor found problems. fix above, re-run.%s\n' "$C_RED" "$C_RESET"
  exit 1
fi
printf '%sdoctor: all green.%s\n' "$C_GREEN" "$C_RESET"
