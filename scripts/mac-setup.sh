#!/bin/sh
# One-time setup of a Mac for a private suffix: send its DNS lookups to your DNS server and trust the
# proxy's local root certificate. Run with sudo. Output goes to /tmp/durin-mac-setup.log as well.
#   sudo sh mac-setup.sh <root.crt> <suffix> <dns server address> [auth host]
set -eu
ROOT="${1:?usage: sudo sh mac-setup.sh root.crt suffix dns-server [auth-host]}"
SUFFIX="${2:?suffix, e.g. home}"
DNS="${3:?DNS server address}"
AUTH="${4:-auth.$SUFFIX}"
case "$SUFFIX" in ""|*[!a-z0-9.-]*) echo "suffix: lower-case letters, digits, dots and dashes only"; exit 1;; esac
case "$DNS" in ""|*[!0-9a-fA-F:.]*) echo "dns server: an IP address"; exit 1;; esac
case "$AUTH" in ""|*[!a-z0-9.-]*) echo "auth host: lower-case letters, digits, dots and dashes only"; exit 1;; esac
[ -f "$ROOT" ] || { echo "no such file: $ROOT"; exit 1; }
LOG=/tmp/durin-mac-setup.log
{
  echo "== $(date)"
  mkdir -p /etc/resolver
  printf 'nameserver %s\n' "$DNS" > "/etc/resolver/$SUFFIX"
  echo "wrote /etc/resolver/$SUFFIX"
  security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$ROOT"
  echo "trusted $(openssl x509 -in "$ROOT" -noout -subject)"
  dscacheutil -flushcache
  killall -HUP mDNSResponder || true
  echo "flushed DNS cache"
  sleep 1
  dscacheutil -q host -a name "$AUTH"
  curl -s -o /dev/null -w "https://$AUTH/ -> %{http_code}\n" "https://$AUTH/" || echo "curl to $AUTH failed"
} 2>&1 | tee "$LOG"
