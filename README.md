# Durin

One passkey sign-in for all your self-hosted apps.

Durin sits behind your reverse proxy. Sign in once at `auth.example.com` and every app on `*.example.com` opens. No passwords, no email, no outside service.

- **Passkeys only** — Face ID, Touch ID, a phone or a security key. No password to type, reuse or leak.
- **Private TLDs** — use names you make up, like `photos.home`, with no domain to buy and nothing public. Single sign-on usually shares one cookie across a domain, which browsers refuse on a bare TLD; Durin gives each app its own.
- **Several domains, one sign-in** — `notes.example.com` and `photos.home` open together.
- **Your proxy** — Caddy, nginx, Traefik, Envoy or HAProxy.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/img/dark.png">
  <img src="docs/img/light.png" alt="Durin's sign-in page and account page">
</picture>

## Install

```sh
git clone https://github.com/joedzado/durin && cd durin
./install.sh auth.example.com caddy
```

<img src="docs/img/install.svg" alt="1. Run install.sh with your sign-in address and your proxy. 2. Paste what it prints into the proxy. 3. Open the link to make your account.">

The first run also installs [Revet](https://github.com/joedzado/revet), the C++ framework Durin is written in.

### On a private TLD

1. **Install** with any name you like:

   ```sh
   ./install.sh auth.home caddy
   ```

2. **Point the name at your server.** In your DNS server (Pi-hole, AdGuard Home, your router), send `*.home` to the machine running the proxy.

3. **Trust the certificate** on each device, once. Caddy makes its own, since nobody sells one for `home`. On macOS or Linux:

   ```sh
   sudo sh scripts/trust.sh root.crt home
   ```

Where to find `root.crt`, what to do on an iPhone, and choosing a name: [Private TLDs](docs/private-names.md).

**Already have Durin on a real domain?** Add `DURIN_DOMAINS=home` to `.env.local` and run `./install.sh`. The same sign-in opens both.

## Use

- **Protect an app:** add the app rule that `install.sh` printed. With Caddy that is one line, `import durin`.
- **Invite someone:** sign in at `auth.example.com` and press *New invite link*. There is no other way to get an account.
- **Know who it is:** your app gets the account name in the `Remote-User` header.
- **Sign out:** once, everywhere.
- **Update:** `git pull && ./install.sh`
- **Lost your passkey, or want a second owner:** run `./durin owner` on the server for a new owner link.

Everyone with an account can open every app; Durin has no per-app permissions and is not an OIDC provider. Pick the sign-in name carefully: passkeys belong to it and do not survive a rename.

## Small

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/img/compare-dark.svg">
  <img src="docs/img/compare-light.svg" alt="Memory, idle: Durin 7 MB, Authelia 72 MB. Size: Durin 5 MB, Authelia 26 MB, Authentik 473 MB.">
</picture>

<sub>Measured November 2026 on Apple silicon. Memory: the running process, on the same machine (Authelia 4.39 in a container, without its Redis; Authentik not measured). Size: Durin's program; the others' compressed container images, with Postgres for Authentik 2026.8.</sub>

## Settings

None are needed. To change one, add it to `.env.local` and run `./install.sh`.

| Setting | Default | |
|---|---|---|
| `DURIN_DOMAINS` | | More domains you control for apps, such as `home,example.org` |
| `DURIN_IDLE_SECONDS` | `300` | Sign out after this long without activity |
| `DURIN_MAX_SECONDS` | `43200` | Sign out after this long regardless |
| `DURIN_REMEMBER_SECONDS` | `2592000` | How long "Remember me" lasts |
| `DURIN_USER_HEADER` | `Remote-User` | Header with the account name |
| `DURIN_PORT` | `3130` | Local port |

## More

- [Proxy recipes](docs/proxies.md)
- [Security](SECURITY.md): how it works, what it protects against, what it does not. Not independently audited.

MIT license.
