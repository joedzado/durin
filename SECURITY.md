# Security

Durin sits in front of other applications and decides who may reach them, so this lists what it defends, what it relies on, and what it does not do.

## How it works

1. The proxy asks Durin about each request. Durin looks for a cookie made for that exact host; if its session is live, it answers 200 and the account name.
2. Otherwise the browser goes to `/.durin/start` on the app's host, which sets a random nonce cookie there and sends it on to the sign-in host with the nonce's hash.
3. After a passkey check, the sign-in host sends the browser back to `/.durin/callback` with a one-time code bound to that host and nonce.
4. The callback swaps the code for a cookie on that host. Every cookie names a server-side session under the sign-in.

## What it defends

| Threat | Defence |
|---|---|
| Open redirect after sign-in | The return address must be `https`, an app host under the suffix, with no user info, odd port or scheme-relative path; anything else is dropped |
| Stealing or replaying the hand-off code | One-time, 60 seconds, bound to the app host, stored hashed, and spent by any attempt, right or wrong |
| One app reading another app's session | Each host has its own `__Host-` cookie (Secure, HttpOnly, no Domain); a cookie opens only the host it was made for, never the auth host |
| Signing someone into your account (login CSRF) | A sign-in starts on the app host, which plants a nonce cookie; the code is bound to the nonce's hash and refuses any browser without the matching cookie, so a code you make cannot be delivered to someone else |
| Session fixation | Every sign-in and every hand-off mints a new random token; only a hash is stored |
| A session that cannot be revoked | Sessions are server-side rows; sign-out ends the sign-in and every app session under it immediately |
| Forged forwarding headers | Each check endpoint reads only headers its proxies overwrite, and its answer goes only to whoever asked. Pages and the hand-off go by `Host` alone |
| CSRF | Every route except the `/.durin/*` GETs takes the framework's CSRF token |
| Framing, caching and referrer leaks | `X-Frame-Options: DENY`, a CSP with `frame-ancestors 'none'`, `Cache-Control: no-store` and `Referrer-Policy: no-referrer` on every response (sign-in addresses and invite links carry secrets in the query string) |
| Making an account uninvited | Accounts come only from one-use links with a 256-bit code, stored hashed: an owner's invite (seven days), or an owner link made on the server's command line (one hour, newest only). Passkey routes are rate limited per address |
| Malformed passkey data | Verification is the Revet framework's WebAuthn code (strict CBOR with size and count caps, RP ID and origin checks, user verification required) |

## What you must provide

- **TLS at the proxy.** Passkeys and `__Host-` cookies need HTTPS.
- **A proxy that removes client-sent copies of the user header** (`Remote-User` by default) and of the forwarding headers it relies on. The recipes in [docs/proxies.md](docs/proxies.md) do.
- **Durin reachable only by the proxy.** It listens on `127.0.0.1`.
- **A secret `.env.local`** (mode 600). Rotating `REVET_COOKIE_KEY` signs everyone out.
- **Backups of `data/`**, and shell access to the server only for people you trust: they can make owners.

## What it does not do

- **Per-app permissions.** Every account opens every gated host. An app that needs more must decide for itself from the user header.
- **Audit logging beyond the log file.** Sign-ins, sign-ups, invites and removals are logged by account name; denied requests are not.
- **Demoting owners.** Owners cannot be removed from the web. Whoever holds an owner's passkey can invite anyone.
- **Protection from a compromised proxy or host.** Either can mint what Durin would answer.
- **A restricted certificate list.** If you use Caddy's on-demand certificates, `GET /.durin/ask` approves any well-formed name under the suffix, so anyone who can reach the proxy can have it issue certificates for made-up names. Keep the proxy off the open internet, or answer the check from your own list.
- **Hiding the session cookie from apps.** The proxy forwards the host's `__Host-durin` cookie to the app unless you strip it; the app can use it only on its own host.
- **Keeping invite links out of logs.** An invite link carries its code in the query string, so it appears in the proxy's access log; it works once and for seven days. Cancel unused links from the account page.

Durin has not had an independent security review.

## Reporting a problem

Please report vulnerabilities privately, not in a public issue: on the repository's GitHub page, open the Security tab and choose "Report a vulnerability". Include what you did and what you saw. Durin has one maintainer, so expect a reply within a few days rather than hours.
