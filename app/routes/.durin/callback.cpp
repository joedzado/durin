#include <revet/web.hpp>
#include "durin.hpp"

// GET /.durin/callback?code=...&rd=/path on an app host: swap the one-time code from the auth host for a
// host-only cookie on this host, then go back to where the visitor was.
static auto render_get(const web::Request& req) -> web::Response {
    const auto host = durin::request_host(req);
    if (!durin::is_app_host(host)) {
        return web::Response{.body = "not found", .content_type = "text/plain", .status = web::status::not_found};
    }
    std::string back = req.query.get("rd", "/");
    if (!durin::is_local_path(back)) back = "/";

    auto h = resources::main_db<db::Write>();
    const auto got = durin::redeem_code(h, req.query.get("code"), host);
    if (!got) {
        // Spent, expired or for another host. Start over; a live sign-in makes this quick.
        return web::redirect(durin::auth_url("/?rd=" + sanitize::url_encode("https://" + host + back)), web::status::found);
    }
    auto resp = web::redirect(back, web::status::found);
    durin::set_cookie(resp, got->started.token, got->remember, got->expires_at - durin::now());
    return resp;
}
