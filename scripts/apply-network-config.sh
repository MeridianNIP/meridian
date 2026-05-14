#!/usr/bin/env bash
# =====================================================================
# Meridian · apply-network-config
# =====================================================================
# Renders /etc/meridian/network-config.json into the actual system
# files (systemd-networkd profile, resolved.conf, timesyncd.conf, proxy
# env, apt proxy), then reloads the relevant services.
#
# Invoked by the portal over sudo via the meridian-network drop-in;
# never run directly.
#
# Sections:
#   ip       — network mode (dhcp|static), addresses, gateway, MTU
#   dns      — DNS servers, search domains
#   ntp      — NTP servers
#   proxy    — HTTP/HTTPS/NO proxy
#
# The config JSON shape is documented in app/reports/... no, in
# app/admin/network_config.py (Pydantic models validate server-side).
# =====================================================================

set -uo pipefail

CONF="/etc/meridian/network-config.json"
if [[ ! -r "$CONF" ]]; then
  echo "missing or unreadable: $CONF" >&2
  exit 2
fi

_get() { jq -r "$1 // empty" "$CONF"; }
_arr() { jq -r "$1 // [] | .[]" "$CONF"; }

# ---- IP / routing ---------------------------------------------------------
apply_ip() {
  local mode addr gw mtu search iface
  mode=$(_get '.ip.mode')
  addr=$(_get '.ip.address_cidr')
  gw=$(_get '.ip.gateway')
  mtu=$(_get '.ip.mtu')
  iface=$(_get '.ip.iface')

  # Idempotent guard: do nothing unless the operator has actually asked
  # for a change. "Empty + DHCP" means the portal form was untouched —
  # writing a profile in that case flaps the network for no reason.
  # Only act when mode=static with an address, OR any IP-section field is set.
  if [[ "$mode" != "static" && -z "$addr" && -z "$gw" && -z "$mtu" && -z "$iface" ]]; then
    echo "apply-network-config: ip section empty — skipping (no change)"
    return 0
  fi
  if [[ "$mode" == "static" && -z "$addr" ]]; then
    echo "apply-network-config: ip mode=static but no address — refusing" >&2
    return 2
  fi

  [[ -z "$iface" ]] && iface=$(ip -o -4 route show default | awk '{print $5; exit}')
  [[ -z "$iface" ]] && iface="eth0"
  search=$(_arr '.dns.search' | paste -sd' ' -)

  local dns=""
  while IFS= read -r d; do [[ -n "$d" ]] && dns+=" $d"; done < <(_arr '.dns.servers')

  local out=/etc/systemd/network/10-meridian.network
  {
    echo "# Portal-managed · Admin Panel → Network Configuration"
    echo "# Regenerated on every apply; edit the portal, not this file."
    echo "[Match]"
    echo "Name=$iface"
    echo
    echo "[Network]"
    if [[ "$mode" == "static" ]]; then
      echo "DHCP=no"
      echo "Address=$addr"
      [[ -n "$gw" ]]     && echo "Gateway=$gw"
      [[ -n "$dns" ]]    && for d in $dns; do echo "DNS=$d"; done
      [[ -n "$search" ]] && echo "Domains=$search"
    else
      echo "DHCP=yes"
      [[ -n "$dns" ]] && for d in $dns; do echo "DNS=$d"; done
    fi
    [[ -n "$mtu" ]] && { echo; echo "[Link]"; echo "MTUBytes=$mtu"; }
  } > "$out"
  chmod 0644 "$out"
  systemctl reload systemd-networkd 2>/dev/null || systemctl restart systemd-networkd
}

# ---- DNS + search domains (resolved) -------------------------------------
apply_dns() {
  local servers search
  servers=$(_arr '.dns.servers' | paste -sd' ' -)
  search=$(_arr '.dns.search' | paste -sd' ' -)
  if [[ -z "$servers" && -z "$search" ]]; then
    echo "apply-network-config: dns section empty — skipping"
    return 0
  fi
  local out=/etc/systemd/resolved.conf.d/10-meridian.conf
  mkdir -p "$(dirname "$out")"
  {
    echo "# Portal-managed · Admin Panel → Network Configuration"
    echo "[Resolve]"
    [[ -n "$servers" ]] && echo "DNS=$servers"
    [[ -n "$search" ]]  && echo "Domains=$search"
  } > "$out"
  chmod 0644 "$out"
  if systemctl list-unit-files systemd-resolved.service >/dev/null 2>&1; then
    systemctl restart systemd-resolved 2>/dev/null || true
  fi
}

# ---- NTP (timesyncd) -----------------------------------------------------
apply_ntp() {
  local servers fallback
  servers=$(_arr '.ntp.servers' | paste -sd' ' -)
  fallback=$(_arr '.ntp.fallback' | paste -sd' ' -)
  if [[ -z "$servers" && -z "$fallback" ]]; then
    echo "apply-network-config: ntp section empty — skipping"
    return 0
  fi
  local out=/etc/systemd/timesyncd.conf.d/10-meridian.conf
  mkdir -p "$(dirname "$out")"
  {
    echo "# Portal-managed · Admin Panel → Network Configuration"
    echo "[Time]"
    [[ -n "$servers" ]]  && echo "NTP=$servers"
    [[ -n "$fallback" ]] && echo "FallbackNTP=$fallback"
  } > "$out"
  chmod 0644 "$out"
  systemctl restart systemd-timesyncd 2>/dev/null || true
}

# ---- Outbound proxy -----------------------------------------------------
apply_proxy() {
  local http https noproxy
  http=$(_get '.proxy.http_url')
  https=$(_get '.proxy.https_url')
  noproxy=$(_get '.proxy.no_proxy')
  if [[ -z "$http" && -z "$https" && -z "$noproxy" ]]; then
    echo "apply-network-config: proxy section empty — skipping"
    return 0
  fi

  # 1. /etc/meridian/proxy.env — sourced by meridian systemd units
  {
    echo "# Portal-managed · Admin Panel → Network Configuration"
    [[ -n "$http" ]]    && echo "HTTP_PROXY=$http"
    [[ -n "$http" ]]    && echo "http_proxy=$http"
    [[ -n "$https" ]]   && echo "HTTPS_PROXY=$https"
    [[ -n "$https" ]]   && echo "https_proxy=$https"
    [[ -n "$noproxy" ]] && echo "NO_PROXY=$noproxy"
    [[ -n "$noproxy" ]] && echo "no_proxy=$noproxy"
  } > /etc/meridian/proxy.env
  chmod 0644 /etc/meridian/proxy.env

  # 2. /etc/apt/apt.conf.d/80meridian-proxy — apt respects its own knob
  {
    echo "// Portal-managed · Admin Panel → Network Configuration"
    [[ -n "$http" ]]  && echo "Acquire::http::Proxy  \"$http\";"
    [[ -n "$https" ]] && echo "Acquire::https::Proxy \"$https\";"
  } > /etc/apt/apt.conf.d/80meridian-proxy
  chmod 0644 /etc/apt/apt.conf.d/80meridian-proxy

  # 3. /etc/systemd/system.conf.d/10-meridian-proxy.conf — systemd-managed
  #    services inherit the vars.
  mkdir -p /etc/systemd/system.conf.d
  {
    echo "# Portal-managed · Admin Panel → Network Configuration"
    echo "[Manager]"
    [[ -n "$http" ]]    && echo "DefaultEnvironment=HTTP_PROXY=$http"
    [[ -n "$https" ]]   && echo "DefaultEnvironment=HTTPS_PROXY=$https"
    [[ -n "$noproxy" ]] && echo "DefaultEnvironment=NO_PROXY=$noproxy"
  } > /etc/systemd/system.conf.d/10-meridian-proxy.conf

  systemctl daemon-reexec 2>/dev/null || true
  systemctl restart meridian-app.service 2>/dev/null || true
}

# ---- Dispatch ------------------------------------------------------------
case "${1:-all}" in
  ip)    apply_ip ;;
  dns)   apply_dns ;;
  ntp)   apply_ntp ;;
  proxy) apply_proxy ;;
  all)   apply_dns; apply_ntp; apply_proxy; apply_ip ;;  # IP last — it can kick the session
  *)     echo "usage: $0 {ip|dns|ntp|proxy|all}" >&2; exit 2 ;;
esac

echo "apply-network-config: section=${1:-all} done"
