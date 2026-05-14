#!/bin/bash
# System update + optional reboot, invoked by the Meridian portal under
# sudo (via /etc/sudoers.d/meridian-updates). Exits 0 on successful
# upgrade; non-zero surfaces to the SystemUpdateRun.exit_code column.
#
# Usage:
#   system-update.sh                # apt update + apt upgrade -y only
#   system-update.sh --reboot       # ... then schedule a 10s-delayed reboot
#
# The reboot is delayed so the HTTP response finishes returning before
# the host pulls the rug. Running as root via sudo — never invoke from
# user code without the sudoers wrapper.
set -e
set -o pipefail

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_SUSPEND=1

REBOOT=0
[[ "${1:-}" == "--reboot" ]] && REBOOT=1

echo "=== apt-get update ==="
apt-get update

echo
echo "=== apt-get upgrade -y ==="
apt-get -y -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" \
            upgrade

echo
echo "=== apt-get autoremove -y ==="
apt-get -y autoremove

if [[ -f /var/run/reboot-required ]]; then
  echo "/var/run/reboot-required present — reboot flagged by apt"
fi

if [[ "$REBOOT" == "1" ]]; then
  echo
  echo "=== scheduling reboot in 10s ==="
  # Detach so this script can exit cleanly before the reboot fires —
  # otherwise the caller's subprocess sees a SIGTERM from shutdown before
  # it has a chance to persist the exit code to Postgres.
  nohup bash -c 'sleep 10 && /bin/systemctl reboot' >/dev/null 2>&1 &
fi

echo "=== done ==="
exit 0
