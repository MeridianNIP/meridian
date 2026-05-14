#!/usr/bin/env bash
# =====================================================================
# Meridian · preflight
# =====================================================================
# Run on the target Debian host BEFORE `install.sh`. Catches every boot-
# time failure static analysis can anticipate: OS version, Python, apt
# resolvability, PostgreSQL compatibility, pip installability, systemd unit
# + nginx + bind + apparmor syntax, and (optionally) network egress to the
# services Meridian depends on.
#
# Non-destructive by default — no services started, no files written outside
# /tmp, no database mutated. Each deeper mode opts into more work.
#
# Usage:
#   sudo ./scripts/preflight.sh              # basic: OS + python + apt resolvability
#   sudo ./scripts/preflight.sh --deep       # + systemd-analyze, nginx -t, named-checkconf, apparmor_parser
#   sudo ./scripts/preflight.sh --full       # + pip install --dry-run, schema load into throwaway DB
#   sudo ./scripts/preflight.sh --egress     # + reach-test the external services Meridian talks to
#   sudo ./scripts/preflight.sh --json       # emit results as a JSON array on stdout
#   sudo ./scripts/preflight.sh --deep --full --egress --json
# =====================================================================

set -uo pipefail

C_RESET=$'\e[0m'; C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'; C_RED=$'\e[31m'; C_DIM=$'\e[2m'; C_BOLD=$'\e[1m'

MODE_DEEP=0; MODE_FULL=0; MODE_EGRESS=0; MODE_JSON=0
while (( $# )); do
  case "$1" in
    --deep)    MODE_DEEP=1 ;;
    --full)    MODE_FULL=1; MODE_DEEP=1 ;;
    --egress)  MODE_EGRESS=1 ;;
    --json)    MODE_JSON=1 ;;
    -h|--help) grep -E '^# ' "$0" | head -25; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done

# Discover repo root — preflight.sh lives in scripts/ within the unpacked tree
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

FAIL=0
WARN=0
declare -a REPORT=()

section() { (( MODE_JSON )) || printf '\n%s── %s ──%s\n' "$C_BOLD" "$1" "$C_RESET"; }
pass()    { (( MODE_JSON )) || printf '  %s✓%s %-36s %s%s%s\n' "$C_GREEN" "$C_RESET" "$1" "$C_DIM" "${2:-}" "$C_RESET"
            REPORT+=("{\"check\":\"$1\",\"result\":\"pass\",\"detail\":\"${2:-}\"}")
          }
warn()    { (( MODE_JSON )) || printf '  %s!%s %-36s %s\n' "$C_YELLOW" "$C_RESET" "$1" "${2:-}"
            REPORT+=("{\"check\":\"$1\",\"result\":\"warn\",\"detail\":\"${2:-}\"}")
            WARN=$((WARN+1))
          }
fail()    { (( MODE_JSON )) || printf '  %s✗%s %-36s %s\n' "$C_RED" "$C_RESET" "$1" "${2:-}"
            REPORT+=("{\"check\":\"$1\",\"result\":\"fail\",\"detail\":\"${2:-}\"}")
            FAIL=$((FAIL+1))
          }

# --------------------------------------------------------------------
# 1 · Host basics
# --------------------------------------------------------------------
section "Host"

if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  case "$ID:${VERSION_ID%%.*}" in
    debian:13) pass "OS" "Debian 13 (primary target)" ;;
    debian:12) pass "OS" "Debian 12 (supported fallback)" ;;
    debian:*)  warn "OS" "Debian $VERSION_ID — only 12 and 13 are tested" ;;
    *)         fail "OS" "$PRETTY_NAME — Meridian targets Debian 12/13 only" ;;
  esac
else
  fail "OS" "/etc/os-release not readable"
fi

ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
case "$ARCH" in
  amd64|x86_64) pass "arch" "$ARCH" ;;
  arm64|aarch64) warn "arch" "$ARCH — tested on amd64 primarily" ;;
  *) fail "arch" "$ARCH — unsupported" ;;
esac

pass "kernel" "$(uname -r)"

if [[ $EUID -ne 0 ]]; then
  warn "privilege" "not running as root — some checks will be skipped. Rerun with sudo."
fi

# --------------------------------------------------------------------
# 2 · Python
# --------------------------------------------------------------------
section "Python"

if command -v python3 >/dev/null; then
  PY_VER=$(python3 -c 'import sys; print(".".join(str(x) for x in sys.version_info[:3]))')
  # Meridian needs 3.11+ for pep-604 unions, pattern matching, etc.
  PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
  PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
  if (( PY_MAJOR == 3 && PY_MINOR >= 11 )); then
    pass "python3" "$PY_VER"
  else
    fail "python3" "$PY_VER — need 3.11 or newer"
  fi
else
  fail "python3" "not installed"
fi

if ! command -v pip3 >/dev/null && ! python3 -m pip --version >/dev/null 2>&1; then
  warn "pip" "not installed — install.sh will apt-get it"
else
  pass "pip" "$(python3 -m pip --version 2>/dev/null | awk '{print $2}')"
fi

# --------------------------------------------------------------------
# 3 · Disk + memory
# --------------------------------------------------------------------
section "Resources"

FREE_GB=$(df --output=avail / | tail -1 | awk '{printf "%d", $1/1024/1024}')
if (( FREE_GB >= 20 )); then
  pass "disk /" "${FREE_GB} GB free"
elif (( FREE_GB >= 10 )); then
  warn "disk /" "${FREE_GB} GB free — 20+ GB recommended"
else
  fail "disk /" "${FREE_GB} GB free — install will likely fail"
fi

MEM_MB=$(awk '/^MemTotal:/ {printf "%d", $2/1024}' /proc/meminfo)
if (( MEM_MB >= 3800 )); then
  pass "memory" "${MEM_MB} MB"
elif (( MEM_MB >= 1900 )); then
  warn "memory" "${MEM_MB} MB — 4+ GB recommended"
else
  fail "memory" "${MEM_MB} MB — too small"
fi

# --------------------------------------------------------------------
# 4 · apt package resolvability
# --------------------------------------------------------------------
section "apt"

if command -v apt-get >/dev/null; then
  pass "apt-get" "$(apt-get --version 2>/dev/null | head -1 | awk '{print $2}')"
  if [[ $EUID -eq 0 ]]; then
    apt-get update -qq >/dev/null 2>&1 \
      && pass "apt-get update" "reachable" \
      || warn "apt-get update" "non-zero exit — check network or sources.list"
  fi
  # Verify every package Meridian installs is findable. The same list lives in
  # install.sh; keep in sync — if it drifts, preflight is the canary.
  CORE_PKGS=(
    nginx bind9 certbot python3-certbot-nginx
    fail2ban openssl apparmor apparmor-utils
    python3 python3-venv python3-pip python3-dev
    build-essential libpq-dev libssl-dev libffi-dev
    libldap2-dev libsasl2-dev
    iproute2 tcpdump dnsutils whois nmap snmp rsync gnupg unzip zstd ufw
  )
  # PostgreSQL major depends on Debian major
  case "${VERSION_ID%%.*}" in
    13) CORE_PKGS+=("postgresql-17") ;;
    12) CORE_PKGS+=("postgresql-15") ;;
  esac
  # Cache/broker depends on Debian major
  case "${VERSION_ID%%.*}" in
    13) CORE_PKGS+=("valkey-server") ;;
    12) CORE_PKGS+=("redis-server") ;;
  esac

  MISSING=()
  for p in "${CORE_PKGS[@]}"; do
    if ! apt-cache policy "$p" 2>/dev/null | grep -q "Candidate:"; then
      MISSING+=("$p")
    fi
  done
  if (( ${#MISSING[@]} == 0 )); then
    pass "apt candidates" "${#CORE_PKGS[@]} pkgs resolvable"
  else
    fail "apt candidates" "${#MISSING[@]} missing: ${MISSING[*]}"
  fi
else
  fail "apt-get" "missing — this script only targets Debian"
fi

# --------------------------------------------------------------------
# 5 · Repo layout sanity
# --------------------------------------------------------------------
section "Bundle layout"

for f in install.sh requirements.txt db/schema.sql app/main.py \
         config/nginx.conf.template config/bind9/named.conf.template \
         config/systemd/meridian-app.service.template \
         config/apparmor/opt.meridian.app \
         config/fail2ban/jail.meridian.conf; do
  if [[ -f "$REPO_ROOT/$f" ]]; then
    pass "file: $f" "present"
  else
    fail "file: $f" "missing"
  fi
done

if [[ -d "$REPO_ROOT/db/migrations" ]]; then
  MIG_COUNT=$(find "$REPO_ROOT/db/migrations" -maxdepth 1 -name '[0-9]*_*.sql' | wc -l)
  pass "db/migrations" "$MIG_COUNT migration(s)"
else
  warn "db/migrations" "not present — upgrades in place will not work"
fi

# --------------------------------------------------------------------
# 6 · Python syntax sweep of the bundled app/
# --------------------------------------------------------------------
section "Python bundle"

if command -v python3 >/dev/null; then
  ERRS=$(python3 - <<PY 2>&1
import ast, os
errs = 0
root = "$REPO_ROOT/app"
for r, _, files in os.walk(root):
    for f in files:
        if f.endswith(".py"):
            p = os.path.join(r, f)
            try: ast.parse(open(p).read(), p)
            except SyntaxError as e:
                errs += 1
                print(f"{p}:{e.lineno}: {e.msg}")
print(f"errors:{errs}")
PY
  )
  ERR_COUNT=$(echo "$ERRS" | grep -E '^errors:' | cut -d: -f2)
  if [[ "$ERR_COUNT" == "0" ]]; then
    pass "app/ python syntax" "every .py parses"
  else
    fail "app/ python syntax" "$ERR_COUNT error(s):
$(echo \"$ERRS\" | grep -v '^errors:')"
  fi
fi

# --------------------------------------------------------------------
# 7 · --deep: config template validity
# --------------------------------------------------------------------
if (( MODE_DEEP )); then
  section "Config templates (--deep)"

  TMPDIR=$(mktemp -d /tmp/meridian-preflight.XXXXXX)
  trap "rm -rf $TMPDIR" EXIT

  # Substitute template vars with plausible defaults so the syntax checker
  # doesn't choke on literal ${...} tokens.
  PORTAL_DOMAIN="preflight.local"
  INSTALL_ROOT="/opt/meridian"
  DATA_ROOT="/var/lib/meridian"
  LOG_ROOT="/var/log/meridian"
  CONFIG_ROOT="/etc/meridian"
  DB_USER="meridian"; DB_NAME="meridian"

  # systemd-analyze verify on each unit
  if command -v systemd-analyze >/dev/null; then
    for tpl in config/systemd/*.template; do
      unit="$TMPDIR/$(basename "${tpl%.template}")"
      envsubst < "$REPO_ROOT/$tpl" > "$unit"
      if systemd-analyze verify "$unit" 2>&1 | grep -qE 'error|Failed'; then
        fail "systemd: $(basename $tpl)" "$(systemd-analyze verify "$unit" 2>&1 | head -3)"
      else
        pass "systemd: $(basename $tpl)" "syntax OK"
      fi
    done
  else
    warn "systemd-analyze" "not available — skipped"
  fi

  # nginx -t on the main template (needs nginx installed)
  if command -v nginx >/dev/null; then
    conf="$TMPDIR/nginx.conf"
    envsubst < "$REPO_ROOT/config/nginx.conf.template" > "$conf"
    # nginx -t wants a full nginx.conf with events + http blocks; the Meridian
    # template is a server{} fragment. Wrap it.
    cat > "$TMPDIR/wrapper.conf" <<EOF
events {}
http {
  include $conf;
}
EOF
    if nginx -t -c "$TMPDIR/wrapper.conf" 2>&1 | grep -qE 'syntax is ok'; then
      pass "nginx -t" "template parses"
    else
      fail "nginx -t" "$(nginx -t -c $TMPDIR/wrapper.conf 2>&1 | head -3)"
    fi
  else
    warn "nginx" "not installed — skipped nginx -t (install.sh will install it)"
  fi

  # named-checkconf on bind9 template
  if command -v named-checkconf >/dev/null; then
    conf="$TMPDIR/named.conf"
    envsubst < "$REPO_ROOT/config/bind9/named.conf.template" > "$conf"
    if named-checkconf "$conf" 2>&1 | grep -qiE 'error|fatal'; then
      fail "named-checkconf" "$(named-checkconf $conf 2>&1 | head -3)"
    else
      pass "named-checkconf" "template parses"
    fi
  else
    warn "named-checkconf" "not installed — skipped"
  fi

  # apparmor_parser in preview mode
  if command -v apparmor_parser >/dev/null; then
    if apparmor_parser -p "$REPO_ROOT/config/apparmor/opt.meridian.app" >/dev/null 2>&1; then
      pass "apparmor profile" "parses"
    else
      fail "apparmor profile" "$(apparmor_parser -p $REPO_ROOT/config/apparmor/opt.meridian.app 2>&1 | head -3)"
    fi
  else
    warn "apparmor_parser" "not installed — skipped"
  fi
fi

# --------------------------------------------------------------------
# 8 · --full: pip dry-run + schema load
# --------------------------------------------------------------------
if (( MODE_FULL )); then
  section "Deep install readiness (--full)"

  # pip install --dry-run resolves the dependency graph without installing.
  if python3 -m pip --version >/dev/null 2>&1; then
    DRY_OUT=$(python3 -m pip install --dry-run --quiet \
                -r "$REPO_ROOT/requirements.txt" 2>&1 || true)
    if echo "$DRY_OUT" | grep -qE 'ERROR|could not find'; then
      fail "pip dry-run" "$(echo "$DRY_OUT" | grep -E 'ERROR|could not' | head -3)"
    else
      pass "pip dry-run" "requirements.txt resolves"
    fi
  else
    warn "pip dry-run" "pip not runnable — skipped"
  fi

  # Schema load into a throwaway database. Non-destructive in the sense that
  # we drop the test DB at the end; but it DOES require postgres running and
  # the postgres OS user accessible via sudo.
  if [[ $EUID -eq 0 ]] && command -v psql >/dev/null && \
     sudo -u postgres psql -Aqt -c 'SELECT 1' >/dev/null 2>&1; then
    TESTDB="meridian_preflight_$$"
    sudo -u postgres createdb "$TESTDB" >/dev/null 2>&1
    if sudo -u postgres psql -v ON_ERROR_STOP=1 -d "$TESTDB" \
         -f "$REPO_ROOT/db/schema.sql" >/tmp/preflight-schema.log 2>&1; then
      pass "schema.sql load" "applied to throwaway DB $TESTDB"
      # While we have a DB, walk migrations forward too
      if [[ -x "$REPO_ROOT/scripts/migrate.sh" ]]; then
        MERIDIAN_DB_NAME="$TESTDB" \
        MERIDIAN_MIGRATIONS_DIR="$REPO_ROOT/db/migrations" \
          "$REPO_ROOT/scripts/migrate.sh" >/tmp/preflight-migrate.log 2>&1 \
          && pass "migrations apply" "all clean" \
          || fail "migrations apply" "see /tmp/preflight-migrate.log"
      fi
    else
      fail "schema.sql load" "see /tmp/preflight-schema.log"
    fi
    sudo -u postgres dropdb "$TESTDB" >/dev/null 2>&1 || true
  else
    warn "schema.sql load" "postgres not reachable as postgres user — skipped"
  fi
fi

# --------------------------------------------------------------------
# 9 · --egress: reach-test external services Meridian talks to
# --------------------------------------------------------------------
if (( MODE_EGRESS )); then
  section "Network egress (--egress)"

  probe() {
    local url="$1"; local label="$2"
    if curl -fsS --max-time 6 -o /dev/null "$url" 2>/dev/null; then
      pass "egress: $label" "reachable"
    else
      warn "egress: $label" "could not reach $url (airgapped installs: expected)"
    fi
  }

  probe "https://meridiannip.com/"                   "meridiannip.com (project home)"
  probe "https://api.osv.dev/v1/query"              "OSV.dev (vuln scanner backend)"
  probe "https://crt.sh"                             "crt.sh (CT log search)"
  probe "https://acme-v02.api.letsencrypt.org/directory" "Let's Encrypt ACME"
  probe "https://ipinfo.io/8.8.8.8/json"             "ipinfo.io (ip.reputation wizard)"
  probe "https://internetdb.shodan.io/8.8.8.8"       "Shodan InternetDB"
  probe "https://api.github.com/zen"                 "GitHub API (optional)"
fi

# --------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------
if (( MODE_JSON )); then
  printf '{"fail":%d,"warn":%d,"checks":[%s]}\n' \
    "$FAIL" "$WARN" "$(IFS=,; echo "${REPORT[*]}")"
else
  echo
  if (( FAIL )); then
    printf '%spreflight FAILED%s · %d failing · %d warn%s\n' \
           "$C_RED" "$C_RESET" "$FAIL" "$WARN" ""
    exit 1
  elif (( WARN )); then
    printf '%spreflight PASSED with %d warning(s)%s · install.sh should be safe to run.\n' \
           "$C_YELLOW" "$WARN" "$C_RESET"
  else
    printf '%spreflight: all green.%s install.sh should be safe to run.\n' \
           "$C_GREEN" "$C_RESET"
  fi
fi

exit $(( FAIL > 0 ? 1 : 0 ))
