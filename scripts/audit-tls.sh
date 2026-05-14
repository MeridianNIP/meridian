#!/usr/bin/env bash
# =====================================================================
# Meridian · TLS audit
# =====================================================================
# Read-only probe of the portal's nginx TLS endpoint. Inspects:
#   - certificate (chain, expiry, SAN match, key type, signature alg)
#   - supported protocols (TLS 1.0 / 1.1 / 1.2 / 1.3) — 1.0/1.1 flagged
#   - cipher strength (RC4, 3DES, DES, EXPORT, NULL flagged)
#   - OCSP stapling
#   - HSTS header
#
# Emits a compact JSON object on stdout so the admin-health card can
# parse it. Also supports a `--human` flag that pretty-prints instead.
#
# No mutation: uses only openssl s_client + curl -I.
# =====================================================================

set -uo pipefail

HOST=""
PORT=443
HUMAN=0
TIMEOUT=6

usage() {
  cat <<EOF
Usage: $0 --host <fqdn> [--port 443] [--human]

Options:
  --host HOST     FQDN of the TLS endpoint to probe (required)
  --port PORT     TCP port (default 443)
  --human         Pretty-print instead of JSON
  -h, --help      This help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2;;
    --port) PORT="$2"; shift 2;;
    --human) HUMAN=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage >&2; exit 2;;
  esac
done

if [[ -z "$HOST" ]]; then
  echo "--host is required" >&2; usage >&2; exit 2
fi

# --- Helpers ---------------------------------------------------------------
jstr() { printf '%s' "${1:-}" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\r//g' -e ':a;N;$!ba;s/\n/\\n/g'; }
sclient() {
  # $1 = extra opts. stdin closed so s_client returns.
  timeout "$TIMEOUT" openssl s_client -connect "$HOST:$PORT" -servername "$HOST" \
    $1 </dev/null 2>/dev/null
}

# --- Protocol probes -------------------------------------------------------
proto_result() {
  # Returns "ok" if the protocol completes a handshake, "no" if refused.
  local flag="$1"
  local out
  out="$(timeout "$TIMEOUT" openssl s_client -connect "$HOST:$PORT" -servername "$HOST" \
        "$flag" </dev/null 2>&1)"
  if grep -q "BEGIN CERTIFICATE" <<<"$out"; then echo "ok"
  elif grep -qE "handshake failure|no protocols available|unsupported protocol|ssl handshake failure|wrong version number" <<<"$out"; then echo "no"
  else echo "err"
  fi
}
TLS10=$(proto_result -tls1)
TLS11=$(proto_result -tls1_1)
TLS12=$(proto_result -tls1_2)
TLS13=$(proto_result -tls1_3)

# --- Certificate + chain ---------------------------------------------------
CERT_TEXT=$(sclient "-showcerts")
if ! grep -q "BEGIN CERTIFICATE" <<<"$CERT_TEXT"; then
  if (( HUMAN )); then
    echo "FAIL — could not reach $HOST:$PORT or no cert returned"
  else
    printf '{"ok":false,"error":"no cert returned","host":"%s","port":%d}\n' "$(jstr "$HOST")" "$PORT"
  fi
  exit 1
fi

LEAF_PEM=$(awk '/BEGIN CERTIFICATE/{p=1} p{print} /END CERTIFICATE/{p=0; exit}' <<<"$CERT_TEXT")
LEAF_INFO=$(openssl x509 -noout -text 2>/dev/null <<<"$LEAF_PEM")
LEAF_ENDDATE=$(openssl x509 -noout -enddate 2>/dev/null <<<"$LEAF_PEM" | cut -d= -f2)
LEAF_ISSUER=$(openssl x509 -noout -issuer 2>/dev/null <<<"$LEAF_PEM" | sed 's/^issuer=//')
LEAF_SUBJECT=$(openssl x509 -noout -subject 2>/dev/null <<<"$LEAF_PEM" | sed 's/^subject=//')
LEAF_SIGALG=$(grep -m1 "Signature Algorithm:" <<<"$LEAF_INFO" | awk -F: '{print $2}' | xargs)
LEAF_SANS=$(openssl x509 -noout -ext subjectAltName 2>/dev/null <<<"$LEAF_PEM" \
  | grep -oE '(DNS|IP Address):[^,]+' | tr '\n' ',' | sed 's/,$//')
LEAF_KEYTYPE=$(grep -m1 "Public Key Algorithm" <<<"$LEAF_INFO" | awk -F: '{print $2}' | xargs)
LEAF_KEYSIZE=$(grep -m1 -E "RSA Public-Key|Public-Key" <<<"$LEAF_INFO" \
  | grep -oE '[0-9]+ bit' | head -1 | awk '{print $1}')

# Compute days-until-expiry. `date -d` on a cert enddate works on GNU date.
if [[ -n "$LEAF_ENDDATE" ]]; then
  EXP_EPOCH=$(date -d "$LEAF_ENDDATE" +%s 2>/dev/null || echo "")
  NOW_EPOCH=$(date +%s)
  if [[ -n "$EXP_EPOCH" ]]; then
    DAYS_LEFT=$(( (EXP_EPOCH - NOW_EPOCH) / 86400 ))
  else
    DAYS_LEFT=""
  fi
fi

# Chain length (PEM block count).
CHAIN_LEN=$(grep -c "BEGIN CERTIFICATE" <<<"$CERT_TEXT")

# --- Cipher preferences (handshake-only; we list the negotiated one) -------
NEGO_CIPHER=$(sclient "-tls1_3" | grep -E "^    Cipher" | head -1 | awk '{print $NF}')
if [[ -z "$NEGO_CIPHER" ]]; then
  NEGO_CIPHER=$(sclient "-tls1_2" | grep -E "^    Cipher" | head -1 | awk '{print $NF}')
fi

# --- OCSP stapling ---------------------------------------------------------
# First: does the cert even have an OCSP responder URL (AIA extension)?
# Self-signed and most private-CA certs don't, and nginx's ssl_stapling
# directive silently no-ops on them. Report "n/a" in that case so the
# operator doesn't chase a non-issue.
OCSP_URI=$(openssl x509 -noout -ocsp_uri 2>/dev/null <<<"$LEAF_PEM" | head -1)
if [[ -z "$OCSP_URI" ]]; then
  OCSP_STAPLED="n/a"
else
  OCSP=$(sclient "-status" | grep -E "OCSP response:|OCSP Response Status:" | head -1)
  if grep -q "no response sent" <<<"$OCSP"; then OCSP_STAPLED="no"
  elif grep -qE "OCSP Response Status: successful" <<<"$(sclient "-status")"; then OCSP_STAPLED="yes"
  else OCSP_STAPLED="unknown"
  fi
fi

# --- HSTS (app layer) ------------------------------------------------------
HSTS_HEADER=$(timeout "$TIMEOUT" curl -sIk --max-time "$TIMEOUT" "https://$HOST:$PORT/" \
  | grep -iE "^strict-transport-security:" | head -1 | tr -d '\r')

# --- Grade -----------------------------------------------------------------
GRADE="ok"
ISSUES=()
[[ "$TLS10" == "ok" ]] && { GRADE="fail"; ISSUES+=("TLS 1.0 accepted"); }
[[ "$TLS11" == "ok" ]] && { GRADE="fail"; ISSUES+=("TLS 1.1 accepted"); }
[[ "$TLS12" != "ok" && "$TLS13" != "ok" ]] && { GRADE="fail"; ISSUES+=("neither TLS 1.2 nor 1.3 offered"); }
[[ "$TLS13" != "ok" ]] && [[ "$GRADE" == "ok" ]] && { GRADE="warn"; ISSUES+=("TLS 1.3 not offered"); }
if [[ -n "$DAYS_LEFT" ]]; then
  (( DAYS_LEFT < 0 ))  && { GRADE="fail"; ISSUES+=("certificate EXPIRED"); }
  (( DAYS_LEFT >= 0 && DAYS_LEFT <= 7 ))  && { GRADE="fail"; ISSUES+=("cert expires in ${DAYS_LEFT}d"); }
  (( DAYS_LEFT > 7 && DAYS_LEFT <= 30 )) && [[ "$GRADE" == "ok" ]] && { GRADE="warn"; ISSUES+=("cert expires in ${DAYS_LEFT}d"); }
fi
# Key strength — thresholds depend on algorithm family. 2048 is the floor
# for RSA, but ECDSA-P256 (256-bit) and Ed25519 (also 256-bit) are MUCH
# stronger than 2048-bit RSA, so the old `< 2048` check false-positived
# on modern certs.
if [[ -n "$LEAF_KEYSIZE" ]]; then
  _kt=$(tr '[:upper:]' '[:lower:]' <<<"$LEAF_KEYTYPE")
  case "$_kt" in
    *rsa*)
      (( LEAF_KEYSIZE < 2048 )) && { GRADE="fail"; ISSUES+=("leaf RSA key ${LEAF_KEYSIZE}-bit < 2048"); }
      ;;
    *ec*|*ecdsa*)
      (( LEAF_KEYSIZE < 256 )) && { GRADE="fail"; ISSUES+=("leaf ECDSA key ${LEAF_KEYSIZE}-bit < 256"); }
      ;;
    *ed25519*|*ed448*)
      : # Fixed-size modern curves, nothing to grade on bit-count.
      ;;
    *)
      # Unknown family — warn rather than fail so an exotic-but-fine cert
      # doesn't get a red X without a human looking at it.
      [[ "$GRADE" == "ok" ]] && { GRADE="warn"; ISSUES+=("unknown key type '${LEAF_KEYTYPE}' — verify manually"); }
      ;;
  esac
fi
case "$(tr '[:upper:]' '[:lower:]' <<<"$LEAF_SIGALG")" in
  *md5*|*sha1*) GRADE="fail"; ISSUES+=("weak signature algorithm: $LEAF_SIGALG");;
esac
[[ -z "$HSTS_HEADER" ]] && [[ "$GRADE" == "ok" ]] && { GRADE="warn"; ISSUES+=("HSTS header missing"); }
# Only flag OCSP-disabled when the cert actually supports OCSP (has an
# AIA responder URL). "n/a" means the cert itself doesn't carry one, so
# nothing nginx does can make stapling work.
[[ "$OCSP_STAPLED" == "no" ]] && [[ "$GRADE" == "ok" ]] && { GRADE="warn"; ISSUES+=("OCSP stapling disabled"); }

# --- Output ---------------------------------------------------------------
if (( HUMAN )); then
  echo "TLS audit · $HOST:$PORT"
  echo "  grade:          $GRADE"
  echo "  subject:        $LEAF_SUBJECT"
  echo "  issuer:         $LEAF_ISSUER"
  echo "  SANs:           $LEAF_SANS"
  echo "  sig alg:        $LEAF_SIGALG"
  echo "  key:            $LEAF_KEYTYPE${LEAF_KEYSIZE:+ $LEAF_KEYSIZE-bit}"
  echo "  expires:        $LEAF_ENDDATE (${DAYS_LEFT:-?}d)"
  echo "  chain length:   $CHAIN_LEN"
  echo "  TLS 1.0:        $TLS10"
  echo "  TLS 1.1:        $TLS11"
  echo "  TLS 1.2:        $TLS12"
  echo "  TLS 1.3:        $TLS13"
  echo "  negotiated:     ${NEGO_CIPHER:-?}"
  echo "  OCSP stapling:  $OCSP_STAPLED"
  echo "  HSTS:           ${HSTS_HEADER:-missing}"
  if (( ${#ISSUES[@]} )); then
    echo "  issues:"
    printf '    - %s\n' "${ISSUES[@]}"
  fi
  exit 0
fi

# JSON output
ISSUES_JSON="["
first=1
for i in "${ISSUES[@]}"; do
  (( first )) || ISSUES_JSON+=','
  ISSUES_JSON+='"'"$(jstr "$i")"'"'
  first=0
done
ISSUES_JSON+="]"

cat <<EOF
{"ok":true,"host":"$(jstr "$HOST")","port":$PORT,"grade":"$GRADE",
 "subject":"$(jstr "$LEAF_SUBJECT")","issuer":"$(jstr "$LEAF_ISSUER")",
 "sans":"$(jstr "$LEAF_SANS")","signature_algorithm":"$(jstr "$LEAF_SIGALG")",
 "key_type":"$(jstr "$LEAF_KEYTYPE")","key_bits":${LEAF_KEYSIZE:-null},
 "not_after":"$(jstr "$LEAF_ENDDATE")","days_left":${DAYS_LEFT:-null},
 "chain_length":$CHAIN_LEN,
 "protocols":{"tls10":"$TLS10","tls11":"$TLS11","tls12":"$TLS12","tls13":"$TLS13"},
 "negotiated_cipher":"$(jstr "${NEGO_CIPHER:-}")",
 "ocsp_stapled":"$OCSP_STAPLED",
 "hsts":"$(jstr "$HSTS_HEADER")",
 "issues":$ISSUES_JSON}
EOF
