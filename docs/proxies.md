# Proxy recipes

Every app host needs two rules: `/.durin/*` goes to Durin, and everything else asks Durin first. The sign-in host just goes to Durin. Pass the `Host` header through unchanged.

`install.sh` prints these with your host name filled in.

## Caddy


```caddy
(durin) {
	route {
		reverse_proxy /.durin/* 127.0.0.1:3130
		forward_auth 127.0.0.1:3130 {
			uri /.durin/verify
			copy_headers Remote-User
		}
	}
}

auth.example.com {
	reverse_proxy 127.0.0.1:3130
}

app.example.com {
	import durin
	reverse_proxy 127.0.0.1:8080
}
```

`route { }` keeps the callback ahead of `forward_auth`.

## Caddy with a private suffix

With a private suffix (such as `.home`) and `tls internal`, issue certificates per host on first visit and let Durin approve the names:

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
	# one @matcher + handle per host, each with `import durin`
}
```

## Traefik

ForwardAuth sets `X-Forwarded-Host` and `X-Forwarded-Uri` itself.

```yaml
http:
  middlewares:
    durin:
      forwardAuth:
        address: http://127.0.0.1:3130/.durin/verify
        trustForwardHeader: false
        authResponseHeaders: [Remote-User]
  routers:
    auth:
      rule: Host(`auth.example.com`)
      service: durin
    app-callback:
      rule: Host(`app.example.com`) && PathPrefix(`/.durin/`)
      priority: 100
      service: durin
    app:
      rule: Host(`app.example.com`)
      middlewares: [durin]
      service: app
  services:
    durin:
      loadBalancer:
        servers: [{ url: http://127.0.0.1:3130 }]
    app:
      loadBalancer:
        servers: [{ url: http://127.0.0.1:8080 }]
```

## nginx

`auth_request` accepts only 2xx, 401 and 403, so it calls `/.durin/auth-request`, which answers 401 with the sign-in address in `Location`.

```nginx
server {
    listen 443 ssl;
    server_name auth.example.com;
    location / {
        proxy_pass http://127.0.0.1:3130;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}

server {
    listen 443 ssl;
    server_name app.example.com;

    location /.durin/ {
        proxy_pass http://127.0.0.1:3130;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    location = /_durin {
        internal;
        proxy_pass http://127.0.0.1:3130/.durin/auth-request;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    location / {
        auth_request /_durin;
        auth_request_set $durin_user $upstream_http_remote_user;
        auth_request_set $durin_signin $upstream_http_location;
        error_page 401 =302 $durin_signin;
        proxy_set_header Remote-User $durin_user;
        proxy_pass http://127.0.0.1:8080;
    }
}
```

Don't answer a gated location with `return`: it runs before `auth_request` and skips the check. Proxy to the app instead.

## Envoy

Uses the `ext_authz` HTTP filter. Envoy appends the original path to `path_prefix` and sends no original-URL header of its own, so the config adds `X-Forwarded-Host` and `X-Forwarded-Uri` from Envoy's own view of the request (a client's copies are never sent to Durin). Durin answers `GET /.durin/verify/<path>` for this.

```yaml
http_filters:
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    allowed_headers: {patterns: [{exact: cookie}]}
    http_service:
      server_uri: {uri: "http://127.0.0.1:3130", cluster: durin, timeout: 2s}
      path_prefix: /.durin/verify
      authorization_request:
        headers_to_add:
        - {key: x-forwarded-host, value: "%REQ(:AUTHORITY)%"}
        - {key: x-forwarded-uri, value: "%REQ(:PATH)%"}
      authorization_response:
        allowed_upstream_headers: {patterns: [{exact: remote-user}]}   # overwrites a client's Remote-User
        allowed_client_headers: {patterns: [{exact: location}]}        # the 302 to the sign-in page
- name: envoy.filters.http.router
  typed_config: {"@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router}
```

Routes: `auth.example.com` and the `/.durin/` prefix on every app host go to the `durin` cluster with `ext_authz` switched off (`typed_per_filter_config` → `ExtAuthzPerRoute` with `disabled: true`); everything else goes to the app. Add `use_remote_address: true` to the connection manager so Durin's rate limits see real client addresses.

## HAProxy

HAProxy has no forward-auth directive; it needs a Lua build (`haproxy -vv` shows `+LUA`; Homebrew's bottle lacks it, the official Docker images have it). The script asks Durin about each request and either passes the user on or answers the browser itself.

`durin.lua`:

```lua
local check = "http://127.0.0.1:3130/.durin/auth-request"

core.register_action("durin_auth", { "http-req" }, function(txn)
  local seen = txn.http:req_get_headers()
  local cookies = {}
  for _, v in pairs(seen["cookie"] or {}) do cookies[#cookies + 1] = v end
  local headers = { ["x-original-url"] = { "https://" .. (txn.sf:req_fhdr("host") or "") .. txn.sf:pathq() } }
  if #cookies > 0 then headers["cookie"] = { table.concat(cookies, "; ") } end

  local res = core.httpclient():get({ url = check, headers = headers, timeout = 2000 })
  if res.status == 200 then
    local user = res.headers["remote-user"]
    txn.http:req_set_header("remote-user", user and user[0] or "")
    return
  end
  local where = res.headers["location"]
  if res.status == 401 and where then
    txn:done(txn:reply({ status = 302, reason = "Found", headers = { ["location"] = { where[0] }, ["cache-control"] = { "no-store" } } }))
  else
    txn:done(txn:reply({ status = res.status == 0 and 503 or 403, reason = "Forbidden" }))
  end
end)
```

`haproxy.cfg`:

```haproxy
global
    tune.lua.bool-sample-conversion normal
    lua-load /etc/haproxy/durin.lua

defaults
    mode http
    timeout connect 3s
    timeout client 30s
    timeout server 30s

frontend web
    bind :443 ssl crt /etc/haproxy/certs/
    acl auth_host hdr(host) -i auth.example.com
    acl durin_path path_beg /.durin/
    http-request del-header Remote-User
    http-request set-header X-Original-URL https://%[req.hdr(host)]%[pathq]
    http-request lua.durin_auth if !auth_host !durin_path
    use_backend durin if auth_host or durin_path
    default_backend app

backend durin
    option forwardfor
    server d 127.0.0.1:3130

backend app
    server a 127.0.0.1:8080
```

`X-Original-URL` is set on every request, so a client's copy never gets through, and `Remote-User` is removed before the check can set it.

## Other proxies

| Proxy | Status |
|---|---|
| Nginx Proxy Manager, SWAG, other nginx wrappers | Use the nginx recipe (their "advanced" or custom-location box); not tested |
| Apache httpd | No built-in forward auth (needs a third-party module); no recipe |
| Anything that can call an HTTP URL per request, copy a response header to the app and relay a `Location` | Works if it can send either header style above |
