#!/bin/sh
# Set this computer (macOS or Linux) up for a private TLD: trust the proxy's root certificate and, if you
# give a DNS server, send the TLD's lookups to it.
#   sudo sh trust.sh <root.crt> <tld> [dns server]
set -eu
ROOT="${1:-}"; TLD="${2:-}"; DNS="${3:-}"
die() { echo "$*" >&2; exit 1; }
[ -n "$TLD" ] || die "usage: sudo sh trust.sh <root.crt> <tld> [dns server]"
[ -f "$ROOT" ] || die "no such file: $ROOT"
case "$TLD" in *[!a-z0-9.-]* | -* | .*) die "not a TLD: $TLD (lower case, no leading dot, like home)" ;; esac
case "$DNS" in *[!0-9a-fA-F:.]*) die "not an IP address: $DNS" ;; esac
[ "$(id -u)" = 0 ] || die "run it with sudo"
case "$(head -n 1 "$ROOT")" in *"BEGIN CERTIFICATE"*) ;; *) die "not a PEM certificate: $ROOT" ;; esac

if [ "$(uname)" = Darwin ]; then
    security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$ROOT"
    if [ -n "$DNS" ]; then
        mkdir -p /etc/resolver
        printf 'nameserver %s\n' "$DNS" >"/etc/resolver/$TLD"
    fi
    dscacheutil -flushcache
    killall -HUP mDNSResponder || true
    echo "Done."
    exit 0
fi

# The system's certificates: curl, git and most programs.
if command -v update-ca-certificates >/dev/null; then # Debian, Ubuntu, Alpine, openSUSE
    if [ -d /etc/pki/trust/anchors ]; then D=/etc/pki/trust/anchors; else D=/usr/local/share/ca-certificates; fi
    mkdir -p "$D"
    cp "$ROOT" "$D/private-$TLD.crt"
    chmod 644 "$D/private-$TLD.crt"
    update-ca-certificates >/dev/null
elif command -v update-ca-trust >/dev/null; then # Fedora, RHEL, Arch
    if [ -d /etc/pki/ca-trust/source/anchors ]; then D=/etc/pki/ca-trust/source/anchors; else D=/etc/ca-certificates/trust-source/anchors; fi
    cp "$ROOT" "$D/private-$TLD.crt"
    chmod 644 "$D/private-$TLD.crt"
    update-ca-trust
else
    die "don't know how to add a certificate on this system"
fi
echo "Trusted by the system."

# Chrome and Chromium keep their own list, per user.
USER_NAME="${SUDO_USER:-}"
if [ -n "$USER_NAME" ] && [ "$USER_NAME" != root ]; then
    if command -v certutil >/dev/null; then
        DB="$(getent passwd "$USER_NAME" | cut -d: -f6)/.pki/nssdb"
        CERT="$(mktemp)"; cp "$ROOT" "$CERT"; chmod 644 "$CERT"
        su "$USER_NAME" -s /bin/sh -c 'mkdir -p "$1" && { [ -f "$1/cert9.db" ] || certutil -N -d "sql:$1" --empty-password; }' _ "$DB"
        su "$USER_NAME" -s /bin/sh -c 'certutil -D -d "sql:$1" -n "$2"' _ "$DB" "private-$TLD" 2>/dev/null || true
        su "$USER_NAME" -s /bin/sh -c 'certutil -A -d "sql:$1" -t C,, -n "$2" -i "$3"' _ "$DB" "private-$TLD" "$CERT"
        rm -f "$CERT"
        echo "Trusted by Chrome for $USER_NAME. Restart Chrome."
    else
        echo "For Chrome, install certutil (libnss3-tools on Debian and Ubuntu, nss-tools on Fedora, nss on Arch) and run this again."
    fi
fi
echo "For Firefox: Settings > Privacy & Security > View Certificates > Authorities > Import."

if [ -n "$DNS" ]; then
    if command -v systemctl >/dev/null && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        mkdir -p /etc/systemd/resolved.conf.d
        printf '[Resolve]\nDNS=%s\nDomains=~%s\n' "$DNS" "$TLD" >"/etc/systemd/resolved.conf.d/private-$TLD.conf"
        systemctl restart systemd-resolved
        echo "*.$TLD is looked up at $DNS."
    else
        echo "No systemd-resolved here: make $DNS this computer's DNS server yourself."
    fi
fi
