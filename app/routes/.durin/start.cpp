#include <revet/sanitize.hpp>
#include <revet/web.hpp>
#include "durin.hpp"

// GET /.durin/start?rd=/path on an app host: the first step of a sign-in. Plants a random nonce in a
// cookie that only this host can read, then sends the browser to the auth host with the nonce's hash.
// The code the auth host hands back is bound to that hash, so it works only in this browser.
static auto render_get(const web::Request& req) -> web::Response {
    const auto host = durin::request_host(req);
    if (!durin::is_app_host(host)) {
        return web::Response{.body = "not found", .content_type = "text/plain", .status = web::status::not_found};
    }
    std::string path = req.query.get("rd", "/");
    if (!durin::is_local_path(path)) path = "/";

    const auto nonce = durin::random_token();
    auto resp = web::redirect(durin::auth_url("/?rd=" + sanitize::url_encode("https://" + host + path) + "&n=" + durin::hash(nonce)),
                              web::status::found);
    resp.cookies.data[std::string(durin::nonce_cookie_name)] = nonce;
    return resp;
}
