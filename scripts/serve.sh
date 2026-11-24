#!/bin/sh
# Durin behind a reverse proxy. Settings come from .env.local (see .env.example); the defaults below
# suit a proxy on the same machine.
cd "$(dirname "$0")/.." || exit 1
set -a; [ -f .env.local ] && . ./.env.local; set +a
export REVET_BIND="${REVET_BIND:-127.0.0.1}"
export REVET_TRUSTED_PROXIES="${REVET_TRUSTED_PROXIES:-127.0.0.1,::1}"
export REVET_FORCE_SECURE_COOKIES=1
export REVET_REQUIRE_COOKIE_KEY=1
mkdir -p data
exec ./build/revet --port "${1:-3130}"
