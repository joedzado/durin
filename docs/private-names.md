# Private TLDs

Durin works on any name your own network resolves: `auth.home` for signing in, `photos.home`, `music.home` and so on for apps. Nothing is registered and nothing leaves your network. These examples use `home`.

## The proxy

`./install.sh auth.home caddy` prints Caddy config with `tls internal` on each site, so Caddy makes the certificates itself. To add one to a Durin that signs in elsewhere, put `DURIN_DOMAINS=home` in `.env.local`, run `./install.sh`, and give each app `tls internal` and `import durin`.

With another proxy, give it a certificate from your own authority. Use one certificate per host: Chrome rejects `*.home`.

## Each device, once

**1. Find the name.** In your DNS server (Pi-hole, AdGuard Home, your router), point `*.home` at the machine running the proxy. Devices using that DNS server need nothing more, except Macs, which also need `/etc/resolver/home` (the script below writes it).

**2. Trust the certificate.** Copy Caddy's root certificate to the device. It is `pki/authorities/local/root.crt` in Caddy's data folder: `~/Library/Application Support/Caddy` on macOS, `~/.local/share/caddy` on Linux.

| Device | |
|---|---|
| Mac | `sudo sh scripts/mac-setup.sh root.crt home <dns server>` does both steps |
| iPhone, iPad | AirDrop it, install the profile, then turn it on in Settings › General › About › Certificate Trust Settings |

Whoever has the private key behind that certificate can impersonate any site to a device that trusts it, so leave the key on the server.

## Choosing a name

`internal` is the only name set aside for this. Any other could one day become a real top-level domain. Avoid `local`, which devices look up differently. Passkeys belong to the sign-in name, so a rename means making new ones.

## Many apps in Caddy

To serve `*.home` from one block, let Caddy issue certificates as hosts are first visited, with Durin approving the names:

```caddy
{
	on_demand_tls {
		ask http://127.0.0.1:3130/.durin/ask
	}
}

*.home {
	tls internal {
		on_demand
	}
	# one @matcher and handle per app, each with: import durin
}
```
