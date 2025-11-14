#!/usr/bin/env bash
#
# detailed_webscan_color.sh
# Purpose: human-readable security header / options / cookie / TLS analysis with color-coded output
# Usage: ./detailed_webscan_color.sh https://example.com
#
# WARNING: Only run this on targets you own or have explicit written permission to test.
#

set -euo pipefail

# --- Colors ---
NC="\033[0m"
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
BOLD="\033[1m"

# small helpers
ok()   { printf "${GREEN}[OK]${NC} %s\n" "$1"; }
warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$1"; }
bad()  { printf "${RED}[FAIL]${NC} %s\n" "$1"; }
info() { printf "${BLUE}[INFO]${NC} %s\n" "$1"; }

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 https://example.com"
  exit 2
fi

TARGET_RAW="$1"
if [[ "$TARGET_RAW" =~ ^https?:// ]]; then
  TARGET="$TARGET_RAW"
else
  TARGET="https://$TARGET_RAW"
fi

HOST=$(echo "$TARGET" | sed -E 's#https?://([^/:]+).*#\1#')
PORT=443

# detect tools
CURL=$(command -v curl || true)
OPENSSL=$(command -v openssl || true)
SSLYZE=$(command -v sslyze || true)
SSLSCAN=$(command -v sslscan || true)

echo -e "${BOLD}*** WARNING: run only with explicit written permission for target $HOST ***${NC}"
echo

div(){ printf "\n%s\n\n" "-------------------------------------------------------------------"; }

# Fetch headers (POC)
info "Fetching headers (POC)..."
HEADER_POC_OUTPUT="$($CURL -s -I -k -L "$TARGET" || true)"
BODY="$($CURL -s -L -m 15 -A "detailed_webscan_color/1.0" "$TARGET" || true)"

div

# === Security headers ===
echo -e "${BOLD}Checking Security Headers${NC}"
echo

present=()
missing=()

for h in "Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options" "Referrer-Policy"; do
  if echo "$HEADER_POC_OUTPUT" | grep -i "^$h:" >/dev/null 2>&1; then
    present+=("$h")
  else
    missing+=("$h")
  fi
done

if [[ ${#present[@]} -gt 0 ]]; then
  echo -e "${GREEN}These headers are present:${NC}"
  for x in "${present[@]}"; do
    echo -e "  ${GREEN}• ${x}${NC}"
  done
else
  echo -e "${YELLOW}No important security headers detected.${NC}"
fi

echo
if [[ ${#missing[@]} -gt 0 ]]; then
  echo -e "${RED}These headers are not present:${NC}"
  for x in "${missing[@]}"; do
    case "$x" in
      "X-Frame-Options") echo -e "  ${RED}• X-Frame-Options header is not implemented${NC}" ;;
      "X-Content-Type-Options") echo -e "  ${RED}• X-Content-Type-Options header is not implemented${NC}" ;;
      "Referrer-Policy") echo -e "  ${RED}• Referrer-Policy header is not implemented${NC}" ;;
      *) echo -e "  ${RED}• ${x} header is not present${NC}" ;;
    esac
  done
else
  echo -e "${GREEN}All checked security headers present.${NC}"
fi

div

# Server header disclosure
echo -e "${BOLD}Checking Server Header disclosure${NC}"
sv=$(echo "$HEADER_POC_OUTPUT" | awk -F': ' '/^[sS]erver:/{ $1=""; sub(/^ /,""); print; exit }' | tr -d '\r' || true)
if [[ -n "$sv" ]]; then
  echo -e "${YELLOW}Server header is disclosed:${NC} ${GREEN}${sv}${NC}"
else
  ok "Server header not disclosed."
fi

div

# X-Powered-By
echo -e "${BOLD}Checking X-Powered-BY Header disclosure${NC}"
xp=$(echo "$HEADER_POC_OUTPUT" | awk -F': ' '/^[xX]-[pP]owered-[bB]y:/{ $1=""; sub(/^ /,""); print; exit }' | tr -d '\r' || true)
if [[ -n "$xp" ]]; then
  warn "X-Powered-BY header disclosed: $xp"
else
  ok "X-Powered-BY header is not present."
fi

div

# OPTIONS method
echo -e "${BOLD}Checking for option methods${NC}"
OPTIONS_OUT="$($CURL -s -I -k -X OPTIONS -L "$TARGET" || true)"
if echo "$OPTIONS_OUT" | grep -i "^Allow:" >/dev/null 2>&1; then
  allow=$(echo "$OPTIONS_OUT" | awk -F': ' '/^[Aa]llow:/{ $1=""; sub(/^ /,""); print; exit }' | tr -d '\r' || true)
  if echo "$allow" | grep -Eio "OPTIONS" >/dev/null 2>&1; then
    warn "OPTIONS method is enabled. Allow: ${allow}"
  else
    ok "OPTIONS method not enabled (Allow header present but OPTIONS not listed)."
  fi
else
  # Try no-redirect to inspect raw response
  OPTIONS_NO_REDIRECT="$($CURL -s -I -k --max-redirs 0 -X OPTIONS "$TARGET" || true)"
  if echo "$OPTIONS_NO_REDIRECT" | grep -i "^Allow:" >/dev/null 2>&1; then
    allow=$(echo "$OPTIONS_NO_REDIRECT" | awk -F': ' '/^[Aa]llow:/{ $1=""; sub(/^ /,""); print; exit }' | tr -d '\r' || true)
    if echo "$allow" | grep -Eio "OPTIONS" >/dev/null 2>&1; then
      warn "OPTIONS method is enabled (no-redirect). Allow: ${allow}"
    else
      ok "OPTIONS method not enabled."
    fi
  else
    ok "OPTIONS method is not Enabled."
  fi
fi

div

# Cookie flags
echo -e "${BOLD}Checking Cookie is set without secure flag or not${NC}"
SETCOOKIES=$(echo "$HEADER_POC_OUTPUT" | grep -i '^Set-Cookie:' || true)
if [[ -z "$SETCOOKIES" ]]; then
  ok "No cookies are set."
else
  insecure_any=0
  while IFS= read -r sc; do
    cookie_line=$(echo "$sc" | sed -E 's/^[sS]et-[cC]ookie:[[:space:]]*//')
    has_secure=$(echo "$cookie_line" | grep -i ';\s*secure' || true)
    has_httponly=$(echo "$cookie_line" | grep -i ';\s*httponly' || true)
    echo -e "Cookie: ${cookie_line}"
    if [[ -z "$has_secure" ]]; then
      bad "  -> Missing Secure flag"
      insecure_any=1
    else
      ok "  -> Secure flag present"
    fi
    if [[ -z "$has_httponly" ]]; then
      warn "  -> Missing HttpOnly flag"
      insecure_any=1
    else
      ok "  -> HttpOnly flag present"
    fi
  done <<< "$SETCOOKIES"
  if [[ $insecure_any -eq 0 ]]; then
    ok "All cookies have Secure and HttpOnly flags (best-effort)."
  fi
fi

div

# HEADER POC output
echo -e "${BOLD}HEADER POC${NC}"
echo
echo -e "${BLUE}curl ${TARGET} -I -k${NC}"
echo
printf '%s\n' "$HEADER_POC_OUTPUT"
echo
ok "Command executed successfully."

div

# OPTION POC
echo -e "${BOLD}OPTION POC${NC}"
echo
echo -e "${BLUE}curl -X OPTIONS ${TARGET} -I -k${NC}"
echo
printf '%s\n' "$OPTIONS_OUT"
echo
ok "Command executed successfully."

div

# TLS / SSLCipher check
echo -e "${BOLD}Checking SSL Ciphers${NC}"
echo

if [[ -n "$SSLYZE" ]]; then
  info "sslyze detected; running --regular scan (may take some seconds)..."
  set +e
  SSLYZE_OUT="$($SSLYZE --regular "${HOST}:${PORT}" 2>&1 || true)"
  set -e
  # print with color hints - if 'FAILED' or 'WARNING' appears, highlight
  if echo "$SSLYZE_OUT" | grep -i "FAILED\|WARNING" >/dev/null 2>&1; then
    echo "$SSLYZE_OUT" | sed -E "s/(FAILED)/${RED}\1${NC}/g; s/(WARNING)/${YELLOW}\1${NC}/g"
    warn "sslyze reported warnings/failures. Review output above."
  else
    echo "$SSLYZE_OUT"
    ok "sslyze completed with no obvious failures."
  fi
else
  if [[ -n "$OPENSSL" ]]; then
    warn "sslyze not found — falling back to openssl-based checks (best-effort)."
    echo
    set +e
    CERT_INFO="$($OPENSSL s_client -servername "$HOST" -connect "${HOST}:${PORT}" -brief 2>/dev/null | $OPENSSL x509 -noout -subject -issuer -dates -serial -fingerprint 2>/dev/null || true)"
    set -e
    if [[ -n "$CERT_INFO" ]]; then
      echo "$CERT_INFO"
      ok "Certificate details retrieved via openssl."
    else
      bad "Could not retrieve certificate details via openssl."
    fi
    echo
    echo "Probing TLS versions (best-effort):"
    set +e
    $OPENSSL s_client -connect "${HOST}:${PORT}" -tls1_3 -servername "$HOST" </dev/null >/dev/null 2>&1
    TLS13_OK=$?
    $OPENSSL s_client -connect "${HOST}:${PORT}" -tls1_2 -servername "$HOST" </dev/null >/dev/null 2>&1
    TLS12_OK=$?
    set -e
    if [[ $TLS13_OK -eq 0 ]]; then ok "TLS 1.3: supported"; else warn "TLS 1.3: NOT supported"; fi
    if [[ $TLS12_OK -eq 0 ]]; then ok "TLS 1.2: supported"; else warn "TLS 1.2: NOT supported"; fi
    echo
    info "For a full matrix use sslyze (pipx) or testssl.sh / sslscan."
  else
    bad "Neither sslyze nor openssl are available. Install sslyze or openssl for TLS analysis."
  fi
fi

div

# Compliance quick-check (certificate lifetime)
echo -e "${BOLD}COMPLIANCE / QUICK TLS CHECKS (best-effort)${NC}"
if [[ -n "$OPENSSL" ]]; then
  set +e
  enddate=$($OPENSSL s_client -servername "$HOST" -connect "${HOST}:${PORT}" -brief 2>/dev/null | $OPENSSL x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
  set -e
  if [[ -n "$enddate" ]]; then
    if date -d "$enddate" >/dev/null 2>&1; then
      end_epoch=$(date -d "$enddate" +%s)
      now_epoch=$(date +%s)
      days_left=$(( (end_epoch - now_epoch) / 86400 ))
      echo "Certificate notAfter: ${enddate} (${days_left} days left)"
      if (( days_left > 366 )); then
        warn "Certificate lifespan appears > 366 days — may fail Mozilla intermediate compliance."
      else
        ok "Certificate lifespan within typical recommended limits."
      fi
    else
      echo "Certificate notAfter: ${enddate}"
    fi
  else
    warn "Could not determine certificate expiry date."
  fi
else
  warn "OpenSSL not present; cannot check certificate expiry."
fi

div
echo -e "${GREEN}${BOLD}Scan finished.${NC} Review above output for findings."
echo -e "${YELLOW}Reminder:${NC} This script performs non-exploitative checks. For deeper testing (active exploitation) obtain written authorization."
echo
exit 0
