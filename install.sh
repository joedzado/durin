#!/usr/bin/env bash
# Build Durin, start it, and print what to paste into your proxy. Run it again to update.
set -euo pipefail
cd "$(dirname "$0")"

usage() {
    cat <<'TXT'
usage: ./install.sh <sign-in host> <proxy>     e.g. ./install.sh auth.example.com caddy
       ./install.sh                            update: rebuild and restart
       ./install.sh --uninstall                stop the service (keeps your data)
proxies: caddy, nginx, traefik, envoy, haproxy
TXT
}
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
die() { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }
setting() { [ -f .env.local ] && sed -n "s/^$1=//p" .env.local | head -n 1 || true; }

DIR="$(pwd)"
NAME="durin"
PLIST="$HOME/Library/LaunchAgents/$NAME.plist"
UNIT="$HOME/.config/systemd/user/$NAME.service"
HOST="${1:-}"
PROXY="${2:-}"

case "$HOST" in
    -h | --help) usage; exit 0 ;;
    --uninstall)
        if [ "$(uname)" = Darwin ]; then
            launchctl bootout "gui/$(id -u)/$NAME" 2>/dev/null || true
            rm -f "$PLIST"
        else
            systemctl --user disable --now "$NAME" 2>/dev/null || true
            rm -f "$UNIT"
        fi
        echo "Stopped. Your accounts are still in $DIR/data."
        exit 0 ;;
esac

# Check everything asked for before doing any work.
OLD="$(setting DURIN_AUTH_HOST)"
[ -n "$HOST" ] || HOST="$OLD"
[ -n "$HOST" ] || { usage; exit 1; }
printf '%s' "$HOST" | grep -Eq '^[a-z0-9-]+(\.[a-z0-9-]+)+$' || die "Not a host name: $HOST (lower case, like auth.example.com)"
[ -z "$OLD" ] || [ "$OLD" = "$HOST" ] || die "Already set up for $OLD. Passkeys belong to that name; to start over, remove .env.local and data/."
[ -n "$OLD" ] || [ -n "$PROXY" ] || { usage; exit 1; }
case "$PROXY" in
    "") SECTION="" ;;
    caddy) SECTION="Caddy" ;;
    nginx) SECTION="nginx" ;;
    traefik) SECTION="Traefik" ;;
    envoy) SECTION="Envoy" ;;
    haproxy) SECTION="HAProxy" ;;
    *) usage; exit 1 ;;
esac

if [ ! -f .env.local ]; then
    (umask 077; printf 'DURIN_AUTH_HOST=%s\nDURIN_PORT=%s\nREVET_COOKIE_KEY=%s\n' "$HOST" "${DURIN_PORT:-3130}" "$(openssl rand -hex 32)" >.env.local)
fi
PORT="$(setting DURIN_PORT)"; PORT="${PORT:-3130}"

export PATH="$HOME/.revet/current:/usr/local/bin:/opt/homebrew/bin:$PATH"
if ! grep -qs 'class Expect' "$HOME/.revet/current/include/revet/auth/passkeys.hpp"; then
    say "Installing Revet, Durin's web framework (a few minutes)"
    curl -fsSL https://raw.githubusercontent.com/joedzado/revet/main/install.sh | bash
fi

say "Building"
revet build >build.log 2>&1 || { tail -n 30 build.log; die "Build failed. Full output: $DIR/build.log"; }

if [ "$(uname)" = Darwin ]; then
    mkdir -p "$(dirname "$PLIST")"
    cat >"$PLIST" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$NAME</string>
  <key>ProgramArguments</key><array><string>$DIR/durin</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$DIR/durin.log</string>
  <key>StandardErrorPath</key><string>$DIR/durin.log</string>
</dict></plist>
XML
    launchctl bootout "gui/$(id -u)/$NAME" 2>/dev/null || true
    for _ in 1 2 3 4 5; do launchctl bootstrap "gui/$(id -u)" "$PLIST" 2>/dev/null && break; sleep 1; done
else
    mkdir -p "$(dirname "$UNIT")"
    printf '[Service]\nExecStart="%s/durin"\nRestart=always\n\n[Install]\nWantedBy=default.target\n' "$DIR" >"$UNIT"
    systemctl --user daemon-reload
    systemctl --user enable "$NAME"
    systemctl --user restart "$NAME"
    loginctl enable-linger 2>/dev/null || true
fi
for _ in $(seq 40); do
    curl -fs -o /dev/null "http://127.0.0.1:$PORT/.durin/ask?domain=$HOST" && UP=1 && break
    sleep 0.5
done
[ "${UP:-}" ] || die "Durin did not start. See $DIR/durin.log (macOS) or: journalctl --user -u $NAME"
say "Durin is running on 127.0.0.1:$PORT"

if [ -n "$SECTION" ]; then
    say "1. Add this to $SECTION:"
    awk -v want="## $SECTION" '$0 == want { on = 1; next } /^## / { on = 0 } on' docs/proxies.md |
        sed -e '/^```/d' -e "s/example\.com/${HOST#*.}/g; s/auth\.${HOST#*.}/$HOST/g; s/3130/$PORT/g"
fi
if [ -z "$OLD" ]; then
    say "2. Make your account (link works once, for an hour; ./durin owner prints a new one):"
    ./durin owner
fi
