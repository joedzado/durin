#include <revet/web.hpp>
#include "durin.hpp"

// POST /logout: end this sign-in and every app session under it. everywhere=1: every sign-in the user has.
static auto render_post(const web::Request& req) -> web::Response {
    if (durin::request_host(req) != durin::settings().auth_host) {
        return web::Response{.body = "not found", .content_type = "text/plain", .status = web::status::not_found};
    }
    auto h = resources::main_db<db::Write>();
    if (const auto who = durin::auth_session(h, req)) {
        if (req.form.get("everywhere") == "1") {
            durin::sign_out_everywhere(h, who->user_id);
        } else {
            durin::sign_out(h, who->parent_id);
        }
    }
    auto resp = web::redirect(urls::index);
    resp.cookies.data[std::string(durin::cookie_name)] = "";
    return resp;
}
