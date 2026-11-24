# Durin: agent guide

Passkey gate for a family of hosts (Revet, C++23). A reverse proxy's forward auth asks Durin about every request to a gated host under the suffix; one sign-in at the auth host covers every app. Named for the Doors of Durin. Proxy setup: `docs/proxies.md`.

## Build, run
- Needs Revet 0.4.1 or later (it ships `revet/auth`): `revet build`. `REVET_FRAMEWORK=<checkout> revet build` builds against a framework checkout instead.
- `scripts/serve.sh [port]` (default 3130) loads `.env.local`; copy `.env.example` and fill it in (600, not in git). Required: `REVET_COOKIE_KEY`, `DURIN_AUTH_HOST`. Durin refuses to start without an auth host.
- `DURIN_SETUP_CODE` makes an owner while there is none (`owner_count == 0`) and is ignored otherwise (delete it afterwards). Then only an owner's one-use invite link (account page, 7 days) makes an account. Owners list and remove people; nobody can remove an owner. Recovery for a lost owner is in the README.
- Sessions: `DURIN_IDLE_SECONDS` (300), `DURIN_MAX_SECONDS` (43200), `DURIN_REMEMBER_SECONDS` (30 days, "Remember me").
- Unit tests: `ctest --test-dir build` (`tests/test_durin.cpp`: host and return-address checks, original-request headers, sessions, codes, invites, owners, forward auth, recovery). Keep them passing; a rule change needs a test.
- Browser test (empty database; it creates accounts, so wipe `data/` afterwards):
  `set -a; . ./.env.local; E2E_APPS=a.<suffix>,b.<suffix>,c.<suffix> node tests/e2e/durin_browser.mjs <chromium> <proxy cert> [proxy address[:port]]`
- Mac client setup for a private suffix: `sudo sh scripts/mac-setup.sh <root.crt> <suffix> <dns server>`.

## How it works
1. Proxy: `/.durin/*` on any gated host goes to Durin; everything else passes forward auth → `GET /.durin/verify` (302 on failure) or `/.durin/auth-request` (401 + `Location`, for nginx).
2. The original host and path come from `X-Forwarded-Host`/`-Uri` (`DURIN_PROXY=forwarded`) or `X-Original-URL` (`original`), and only from `REVET_TRUSTED_PROXIES`.
3. verify: a `__Host-durin` cookie naming a live session for that exact host → 200 + `DURIN_USER_HEADER: <name>`. Otherwise to `https://<auth host>/?rd=<original URL>`.
4. Auth host: passkey sign-in (framework `web::auth::passkeys`, RP ID = auth host). Signed in + valid `rd` (https, an app host, no userinfo) → one-time code (60 s, single use, bound to the host) → `https://<host>/.durin/callback?code=…&rd=/path`.
5. callback swaps the code for a host-only cookie on that host. No shared cookie: browsers refuse one on a bare public suffix, and host-only cookies leak less.
6. Every cookie names a row in `durin_sessions`; app-host rows hang off the sign-in row. Sign out revokes the sign-in and all its hosts; "Sign out everywhere" revokes all of the user's.
7. `GET /.durin/ask?domain=` (optional) answers Caddy's on-demand TLS check.
8. Envoy's ext_authz appends the request path to the check address, so `/.durin/verify/<path>` is answered by the 404 handler in `site_init.cpp` (Revet has no catch-all route); host and path come from `X-Forwarded-Host`/`-Uri`, which the Envoy config fills in.

## Rules
- Never gate the auth host.
- CSRF applies to everything except `/.durin/*` (GETs on other apps' hosts; Durin must not plant cookies there).
- Passkey routes answer only on the auth host and carry the framework's rate limits.
- Every response carries the no-store, no-referrer, no-framing headers (`site_init.cpp`); keep them.
- README, SECURITY.md and `docs/` describe Durin alone: no names of people, hosts or other projects.

## Layout
| File | Role |
|---|---|
| `src/durin.hpp` | Settings, original-request headers, host and return-URL checks, schema, sessions, codes, owners and invites, forward auth |
| `app/routes/.durin/` | `verify`, `auth-request` (forward auth), `callback` (code → cookie), `ask` (on-demand TLS) |
| `app/routes/index.cpp` | Auth host: handoff, sign-in page (`?invite=`), account page |
| `app/routes/passkey/` | WebAuthn options/finish for sign-in and registration |
| `app/routes/people/` | Owners: invite, cancel invite, remove person |
| `app/routes/logout.cpp`, `passkeys*.cpp` | Sign out, passkey list and removal |
| `app/components/ui.cpp`, `app/scripts/durin.js` | Pages; passkey ceremonies in the browser (no libraries) |
| `tests/test_durin.cpp` | Unit tests for `src/durin.hpp` on a throwaway SQLite database |
| `tests/e2e/durin_browser.mjs` | Headless Chromium + virtual authenticator through a real proxy |
| `docs/proxies.md` | Caddy, Traefik, nginx, Envoy and HAProxy recipes |
