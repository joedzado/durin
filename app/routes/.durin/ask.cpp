#include <revet/web.hpp>
#include "durin.hpp"

// GET /.durin/ask?domain=<name>: optional, for Caddy's on-demand TLS (on_demand_tls ask). Yes for the auth
// host and any well-formed app host, so a new app host gets a certificate on first visit.
static auto render_get(const web::Request& req) -> web::Response {
    const auto domain = durin::lower(req.query.get("domain"));
    const bool ok = domain == durin::settings().auth_host || durin::is_app_host(domain);
    return web::Response{.body = ok ? "ok" : "no", .content_type = "text/plain", .status = ok ? web::status::ok : web::status::forbidden};
}
