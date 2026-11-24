#include <cstdlib>
#include <revet/auth/passkeys.hpp>
#include <revet/auth/tokens.hpp>
#include <revet/auth/users.hpp>
#include <revet/csrf.hpp>
#include <revet/log.hpp>
#include <revet/web.hpp>
#include "durin.hpp"
#include "resources.hpp"

void site_init() {
    // /.durin/* answers on app hosts (Caddy routes it there). Those are GETs that must not plant Durin's
    // CSRF cookie on another app's host; everything else is the auth host's pages and takes CSRF.
    // Every response: no caching, no framing, no referrer (sign-in addresses and invite links carry secrets
    // in the query string), no sniffing, and scripts only from this host.
    web::use([](const web::Request&, const web::Next& next) -> web::Response {
        auto resp = next();
        auto& h = resp.headers.data;
        h["Cache-Control"] = "no-store";
        h["Referrer-Policy"] = "no-referrer";
        h["X-Content-Type-Options"] = "nosniff";
        h["X-Frame-Options"] = "DENY";
        h["Content-Security-Policy"] =
            "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
        return resp;
    });
    web::use([](const web::Request& req, const web::Next& next) -> web::Response {
        if (req.path.path.starts_with("/.durin/")) return next();
        return web::csrf::middleware(req, next);
    });
    // Envoy ext_authz appends the original path to its check address: GET /.durin/verify/<path>. Revet
    // has no catch-all route yet, so the 404 handler answers those; the original host and path arrive
    // in X-Forwarded-Host and X-Forwarded-Uri, which Envoy fills in (see docs/proxies.md).
    web::on_error(web::status::not_found, [](const web::Request& req) -> web::Response {
        if (req.path.path.starts_with("/.durin/verify/")) {
            auto h = resources::main_db<db::Write>();
            return durin::verify(h, req, true);
        }
        auto resp = web::to_response(std::string("404 Not Found"));
        resp.status = web::status::not_found;
        return resp;
    });
    web::config::secure_cookies(true); // every page is https, and __Host- cookies need Secure

    auto h = resources::main_db<db::Write>();
    web::auth::create_schema(h);
    web::auth::tokens::create_schema(h);
    web::auth::passkeys::create_schema(h);
    durin::create_schema(h);

    const auto& s = durin::settings();
    if (s.auth_host.empty() || s.suffix.empty() || !s.auth_host.ends_with("." + s.suffix)) {
        throw web::StartupError("set DURIN_AUTH_HOST (e.g. auth.example.com), and DURIN_SUFFIX if apps are not its siblings", 1);
    }
    auto& pk = web::auth::passkeys::config();
    pk.rp_name = "Durin";
    pk.rp.rp_id = s.auth_host;
    pk.rp.origins = {"https://" + s.auth_host};
    pk.rp.require_user_verification = true;
    pk.app_link_paths.clear();
    log::info("durin: auth host {}, app hosts *.{}, {} account(s)", s.auth_host, s.suffix, durin::user_count(h));
}
