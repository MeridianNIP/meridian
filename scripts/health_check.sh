#!/usr/bin/env bash
# =====================================================================
# Meridian · One-shot health check
# =====================================================================
# Intended for:
#   · human operators on the box
#   · external probes (exit 0 = all healthy, 1 = problem found)
#   · the Admin → System Health card's "refresh" button
#
# Usage:
#   /opt/meridian/scripts/health_check.sh
#   /opt/meridian/scripts/health_check.sh --json
# =====================================================================

set -uo pipefail

C_RESET=$'\e[0m'; C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'; C_RED=$'\e[31m'; C_DIM=$'\e[2m'
JSON=0
PROBLEMS=0
declare -a REPORT=()

while (( $# )); do
  case "$1" in
    --json) JSON=1 ;;
    -h|--help) grep -E '^# ' "$0" | head -15; exit 0 ;;
  esac
  shift
done

check() {
  local label=$1 ok=$2 detail=$3
  if (( ok )); then
    (( JSON )) || printf "  %s✓%s %-28s %s%s%s\n" "$C_GREEN" "$C_RESET" "$label" "$C_DIM" "$detail" "$C_RESET"
    REPORT+=("{\"check\":\"$label\",\"ok\":true,\"detail\":\"$detail\"}")
  else
    (( JSON )) || printf "  %s✗%s %-28s %s\n" "$C_RED" "$C_RESET" "$label" "$detail"
    REPORT+=("{\"check\":\"$label\",\"ok\":false,\"detail\":\"$detail\"}")
    PROBLEMS=$(( PROBLEMS + 1 ))
  fi
}

# --- Services ---
# Cache service is either valkey-server (Debian 13 / trixie) or redis-server
# (Debian 12 / bookworm). Health-check accepts whichever is installed and
# active; flags the absence of both.
if systemctl list-unit-files valkey-server.service &>/dev/null; then
  CACHE_SVC="valkey-server"
else
  CACHE_SVC="redis-server"
fi
for svc in postgresql "$CACHE_SVC" bind9 nginx fail2ban \
           meridian-app meridian-celery meridian-beat; do
  if systemctl is-active --quiet "$svc" 2>/dev/null; then
    check "service: $svc" 1 "active"
  else
    check "service: $svc" 0 "NOT active"
  fi
done

# --- App /healthz ---
if out=$(curl -fsS --max-time 3 "http://127.0.0.1:8000/healthz" 2>&1); then
  check "app /healthz" 1 "$out"
else
  check "app /healthz" 0 "unreachable"
fi

# --- Disk ---
read -r FS PCT <<<"$(df --output=target,pcent / | tail -1 | tr -d %)"
if (( PCT < 85 )); then
  check "disk / usage" 1 "${PCT}% used"
elif (( PCT < 95 )); then
  check "disk / usage" 1 "${PCT}% used (warning threshold approaching)"
else
  check "disk / usage" 0 "${PCT}% used — CRITICAL"
fi

# --- Memory ---
MEM_PCT=$(free | awk '/^Mem:/ {printf "%d", ($3/$2)*100}')
if (( MEM_PCT < 90 )); then
  check "memory" 1 "${MEM_PCT}% used"
else
  check "memory" 0 "${MEM_PCT}% used — CRITICAL"
fi

# --- Certificate expiry (if the portal cert exists) ---
PORTAL_DOMAIN=$(awk -F'[ \t"=]+' '/^portal_domain/ {print $2}' /etc/meridian/meridian.conf 2>/dev/null || echo "")
if [[ -n "$PORTAL_DOMAIN" ]] && [[ -r "/etc/letsencrypt/live/${PORTAL_DOMAIN}/cert.pem" ]]; then
  EXPIRY=$(openssl x509 -in "/etc/letsencrypt/live/${PORTAL_DOMAIN}/cert.pem" -noout -enddate | cut -d= -f2)
  EXP_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || echo 0)
  NOW=$(date +%s)
  DAYS=$(( (EXP_EPOCH - NOW) / 86400 ))
  if (( DAYS > 30 )); then
    check "cert expiry" 1 "${DAYS} days remaining"
  elif (( DAYS > 7 )); then
    check "cert expiry" 1 "${DAYS} days (renew soon)"
  elif (( DAYS > 0 )); then
    check "cert expiry" 0 "${DAYS} days — RENEW NOW"
  else
    check "cert expiry" 0 "EXPIRED"
  fi
fi

# --- License + DB via the app CLI ---
if [[ -x /opt/meridian/venv/bin/python ]]; then
  if /opt/meridian/venv/bin/python -m app.cli doctor >/dev/null 2>&1; then
    check "app doctor" 1 "all checks pass"
  else
    check "app doctor" 0 "see: meridian-nip doctor"
  fi
fi

# --- Output ---
if (( JSON )); then
  printf '{"ok":%s,"problems":%d,"checks":[%s]}\n' \
    "$( (( PROBLEMS == 0 )) && echo true || echo false )" \
    "$PROBLEMS" \
    "$(IFS=,; echo "${REPORT[*]}")"
fi

exit $(( PROBLEMS > 0 ? 1 : 0 ))
