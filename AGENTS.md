# Durin: agent guide

Passkey gate for a family of hosts (Revet, C++23). A reverse proxy's forward auth asks Durin about every request to a gated host under one of its domains; one sign-in at the auth host covers every app. Named for the Doors of Durin. Proxy setup: `docs/proxies.md`.

## Build, run
- `./install.sh <host> <proxy>` does everything on a new machine; with no arguments it rebuilds and restarts. It prints the matching `## <Proxy>` section of `docs/proxies.md`, replacing `example.com`, `auth.example.com` and `3130`, so recipes keep those placeholders.
- By hand: `revet build` (Revet `main`), then `./durin`. `./durin owner` prints an owner link. Settings: `.env.local`.
- Unit tests: `ctest --test-dir build`. A rule change needs a test.
- Browser test, through a real proxy on an empty database: see the top of `tests/e2e/durin_browser.mjs`.
- A new setting, step or file in the install is a cost to every user: avoid it.

## How it works
1. Proxy: `/.durin/*` on any gated host goes to Durin; everything else passes forward auth → `GET /.durin/verify` (302 on failure) or `/.durin/auth-request` (401 + `Location`, for nginx).
2. Sign-in starts on the app host: verify answers a 302 (or 401 + `Location`) to `https://<app host>/.durin/start?rd=<path>`; `start` plants the `__Host-durin-nonce` cookie and sends the browser to the auth host with `n=<hash of the nonce>`; the auth host binds the one-time code to that hash; `callback` redeems it only with the matching cookie (login-CSRF defence). Never mint a code without a valid `n`.
   `verify` reads X-Forwarded-Host/-Uri, `auth-request` reads X-Original-URL; everything else goes by Host.
3. verify: a `__Host-durin` cookie naming a live session for that exact host → 200 + `DURIN_USER_HEADER: <name>`. Otherwise to the start address above.
4. Auth host: passkey sign-in (framework `web::auth::passkeys`, RP ID = auth host). Signed in + valid `rd` (https, an app host, no userinfo) + valid `n` → one-time code (60 s, single use, bound to the host and the nonce hash) → `https://<host>/.durin/callback?code=…&rd=/path`.
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
| `app/routes/.durin/` | `verify`, `auth-request` (forward auth), `start` (nonce, then auth host), `callback` (code → cookie), `ask` (on-demand TLS) |
| `app/routes/index.cpp` | Auth host: handoff, sign-in page (`?invite=`), account page |
| `app/routes/passkey/` | WebAuthn options/finish for sign-in and registration |
| `app/routes/people/` | Owners: invite, cancel invite, remove person |
| `app/routes/logout.cpp`, `passkeys*.cpp` | Sign out, passkey list and removal |
| `app/components/ui.cpp`, `app/scripts/durin.js` | Pages; passkey ceremonies in the browser (no libraries) |
| `tests/test_durin.cpp` | Unit tests for `src/durin.hpp` on a throwaway SQLite database |
| `tests/e2e/durin_browser.mjs` | Headless Chromium + virtual authenticator through a real proxy |
| `src/main.cpp` | Serve, or `owner` |
| `docs/proxies.md` | Caddy, Traefik, nginx, Envoy and HAProxy recipes |
