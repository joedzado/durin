#include <revet/auth/limits.hpp>
#include <revet/auth/passkeys.hpp>
#include <revet/json.hpp>
#include <revet/log.hpp>
#include "durin.hpp"

// POST /passkey/login/finish: check the passkey, start a sign-in, set its cookie on the auth host.
static auto render_post(const web::Request& req) -> web::Response {
    namespace pk = web::auth::passkeys;
    if (durin::request_host(req) != durin::settings().auth_host) return web::api::error(web::status::not_found, "not_found");
    std::string challenge_id, credential_id, client_data, auth_data, signature, handle;
    bool remember = false;
    try {
        revet::json::Document doc(req.raw_body);
        auto root = doc.root();
        challenge_id = root.get("challenge_id", "");
        credential_id = root.get("credential_id", "");
        client_data = root.get("client_data_json", "");
        auth_data = root.get("authenticator_data", "");
        signature = root.get("signature", "");
        handle = root.get("user_handle", "");
        remember = root.get("remember", "") == "1";
    } catch (const std::exception&) {
        return web::api::error(web::status::bad_request, "bad_request");
    }

    auto h = resources::main_db<db::Write>();
    const auto in = pk::finish_login(h, challenge_id, credential_id, client_data, auth_data, signature, handle);
    if (!in) {
        log::warn("durin: passkey sign-in refused (kind {})", static_cast<int>(in.error().kind));
        return web::api::error(web::status::unauthorized, "login_failed");
    }
    if (durin::name_of(h, in->user_id).empty()) return web::api::error(web::status::unauthorized, "login_failed");
    const auto s = durin::sign_in(h, in->user_id, remember);
    log::info("durin: {} signed in{}", durin::name_of(h, in->user_id), remember ? " (remembered)" : "");
    web::Response resp{.body = R"({"ok":true})", .content_type = "application/json"};
    durin::set_cookie(resp, s.token, remember, durin::settings().remember_seconds);
    return resp;
}

static auto route_guards() -> std::vector<web::Middleware> {
    return web::auth::limits::anonymous();
}
