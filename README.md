# Durin

One passkey sign-in for every app behind your reverse proxy.

Durin is a small forward-auth server. The proxy asks it about each request; Durin answers "signed in as `ann`" or sends the browser to a sign-in page. Sign in once at `auth.example.com` and every app under `*.example.com` opens, with no passwords anywhere. It is a Revet (C++23) application with a SQLite database, one binary, and no JavaScript beyond about 100 lines for the passkey calls.

It works with anything that can ask an HTTP address about each request: Caddy, Traefik, nginx, Envoy and HAProxy have tested recipes in [docs/proxies.md](docs/proxies.md).

## What you get

- Passkeys only (WebAuthn, user verification required). No passwords, no email, no third party.
- One sign-in covers every app host under a suffix. Signing out ends all of them at once, and so does "Sign out everywhere".
- Sessions end after 5 minutes of quiet or 12 hours, or last 30 days with "Remember me" (all configurable).
- The app receives the account name in a header (`Remote-User` by default).
- An owner who invites people with one-use links, lists them, and removes them. Nobody can sign up without a link.
- Each app host has its own cookie that no other app can read, and a stolen cookie from one app opens nothing else.

## What it is not

- Not an authorization system: every account can open every gated host. Put apps that need finer rules behind their own checks and use the `Remote-User` header to tell people apart.
- Not an OIDC or OAuth provider, and it has no groups or roles beyond owner and member.
- One owner at a time, SQLite only, no email (so no email-based recovery; see Recovery).

## How it works

1. The proxy sends `/.durin/*` on every gated host to Durin, and everything else through forward auth to `GET /.durin/verify`.
2. Durin looks for a session cookie (`__Host-durin`) made for that exact host. Found: 200 and the user header. Not found: redirect to `https://auth.example.com/?rd=<original address>`.
3. At the auth host the user signs in with a passkey. Durin then sends the browser back to `https://app.example.com/.durin/callback?code=…` with a one-time code (60 seconds, single use, bound to that host).
4. The callback swaps the code for a cookie that only that host holds.

There is no shared cookie because browsers will not set one on a bare public suffix, and a per-host cookie keeps one compromised app from reading another's session. Every cookie names a server-side session, so sign-out is immediate. Return addresses are checked against the suffix, so the redirect cannot be pointed at another site.

## Run it

You need the [Revet](https://github.com/joedzado/revet) framework (0.4.1 or later, with `revet/auth`), a C++23 compiler, and a reverse proxy that terminates TLS. Passkeys need HTTPS, and a passkey belongs to the auth host name, so changing that name later loses every passkey.

```sh
revet build
cp .env.example .env.local && chmod 600 .env.local
# set REVET_COOKIE_KEY (openssl rand -hex 32), DURIN_AUTH_HOST and DURIN_SETUP_CODE
scripts/serve.sh            # listens on 127.0.0.1:3130
```

Then add the recipe for your proxy from [docs/proxies.md](docs/proxies.md), open `https://auth.example.com`, and make the owner account with the setup code. Delete `DURIN_SETUP_CODE` from `.env.local` afterwards and restart. From then on the owner invites people from the account page.

## Settings

Set in `.env.local`, which `scripts/serve.sh` loads.

| Setting | Default | Meaning |
|---|---|---|
| `REVET_COOKIE_KEY` | required | Secret for sealed cookies and tokens |
| `DURIN_AUTH_HOST` | required | Sign-in host and passkey RP ID, e.g. `auth.example.com` |
| `DURIN_SUFFIX` | auth host minus its first label | Gated hosts are `*.<suffix>` |
| `DURIN_SETUP_CODE` | none | Makes an owner while there is none |
| `DURIN_PROXY` | `forwarded` | `forwarded` (`X-Forwarded-Host`/`-Uri`: Caddy, Traefik, Envoy) or `original` (`X-Original-URL`: nginx, HAProxy) |
| `DURIN_USER_HEADER` | `Remote-User` | Header carrying the account name |
| `DURIN_IDLE_SECONDS` | 300 | A sign-in without "Remember me" ends after this much quiet |
| `DURIN_MAX_SECONDS` | 43200 | ... and after this long in any case |
| `DURIN_REMEMBER_SECONDS` | 2592000 | How long "Remember me" lasts |
| `REVET_TRUSTED_PROXIES` | `127.0.0.1,::1` | Only these peers' forwarding headers are believed |
| `REVET_BIND` | `127.0.0.1` | Listen address; keep Durin off the open network |

## A private suffix (such as `.home`)

A private suffix works, with two extra jobs. Point its DNS at your proxy (a wildcard record in your resolver), and make every device trust the proxy's certificate authority, because no public authority will issue for a made-up name. Chrome also refuses a wildcard certificate directly under a bare suffix, so use one certificate per host (Caddy's `tls internal` with `on_demand` and `on_demand_tls { ask http://127.0.0.1:3130/.durin/ask }` does this). On a Mac, `sudo sh scripts/mac-setup.sh <root.crt> <suffix> <dns server>` adds the resolver entry and trusts the certificate.

## Recovery

There are no email resets. Keep more than one passkey on the owner account (the account page adds them), or keep the database backed up. If the owner is locked out, stop Durin and remove the owner's account, then restart with `DURIN_SETUP_CODE` set and make a new owner. Other accounts are kept.

```sh
sqlite3 data/durin.db "PRAGMA foreign_keys=ON; DELETE FROM auth_users WHERE id IN (SELECT user_id FROM durin_users WHERE owner = 1);"
```

## Build and checks

```sh
revet build
ctest --test-dir build        # unit tests for the rules (sessions, codes, invites, owners, host checks)
```

`tests/e2e/durin_browser.mjs` drives a real Chromium with a virtual authenticator through a real proxy: sign-up, sign-in, the handoff between apps, invites, sign-out and header checks. See the comment at its top for how to run it.

## Security

See [SECURITY.md](SECURITY.md) for the threat model and how to report a problem.

## Licence

MIT. See [LICENSE](LICENSE).
