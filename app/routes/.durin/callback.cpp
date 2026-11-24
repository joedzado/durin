#include <revet/web.hpp>
#include "durin.hpp"

// GET /.durin/callback?code=...&rd=/path on an app host: swap the one-time code from the auth host for a
// host-only cookie on this host, then go back to where the visitor was. The code must have been made for
// the nonce cookie /.durin/start planted in this browser.
static auto render_get(const web::Request& req) -> web::Response {
    const auto host = durin::request_host(req);
    if (!durin::is_app_host(host)) {
        return web::Response{.body = "not found", .content_type = "text/plain", .status = web::status::not_found};
    }
    std::string back = req.query.get("rd", "/");
    if (!durin::is_local_path(back)) back = "/";

    auto h = resources::main_db<db::Write>();
    const auto got = durin::redeem_code(h, req.query.get("code"), host, req.cookies.get(durin::nonce_cookie_name));
    if (!got) {
        // Spent, expired, for another host, or made for another browser. Start over; a live sign-in makes this quick.
        return web::redirect(durin::start_url(host, back), web::status::found);
    }
    auto resp = web::redirect(back, web::status::found);
    resp.cookies.data[std::string(durin::nonce_cookie_name)] = "";
    durin::set_cookie(resp, got->started.token, got->remember, got->expires_at - durin::now());
    return resp;
}
