#include <revet/auth/limits.hpp>
#include <revet/auth/passkeys_http.hpp>
#include "durin.hpp"

// POST /passkey/login/options (auth host only).
static auto render_post(const web::Request& req) -> web::Response {
    if (durin::request_host(req) != durin::settings().auth_host) return web::api::error(web::status::not_found, "not_found");
    return web::auth::passkeys::http::login_options(req, [] { return resources::main_db<db::Write>(); });
}

static auto route_guards() -> std::vector<web::Middleware> {
    return web::auth::limits::anonymous();
}
