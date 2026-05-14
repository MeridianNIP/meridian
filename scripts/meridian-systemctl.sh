#!/bin/bash
# Tightly-scoped wrapper: meridian user invokes via
#   sudo /usr/bin/systemctl <verb> <unit>
# The sudoers drop-in only allows that exact program path. This script
# lives in scripts/ as a reference / snapshot — the real invocation is
# /usr/bin/systemctl directly, sudoers-guarded.
#
# Allowed verbs (enforced at the callsite, not here): start, stop,
# restart, reload, is-active, status, show.
# Allowed units (enforced at the callsite):
#   nginx, bind9, meridian-app, meridian-celery, meridian-beat,
#   fail2ban, redis-server, valkey-server, postgresql.
exec /usr/bin/systemctl "$@"
