#include <revet/web.hpp>
#include "durin.hpp"

// GET /.durin/ask?domain=<name>: optional, for Caddy's on-demand TLS (on_demand_tls ask).
static auto render_get(const web::Request& req) -> web::Response {
    const auto domain = durin::lower(req.query.get("domain"));
    const bool ok = durin::ask_allowed(domain);
    return web::Response{.body = ok ? "ok" : "no", .content_type = "text/plain", .status = ok ? web::status::ok : web::status::forbidden};
}
