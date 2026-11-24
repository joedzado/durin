#include <revet/auth/limits.hpp>
#include <revet/auth/passkeys.hpp>
#include <revet/json.hpp>
#include <revet/json_write.hpp>
#include "durin.hpp"

// POST /passkey/register/options: another passkey for the signed-in user, or a new account with an
// one-use link.
static auto render_post(const web::Request& req) -> web::Response {
    namespace pk = web::auth::passkeys;
    if (durin::request_host(req) != durin::settings().auth_host) return web::api::error(web::status::not_found, "not_found");
    std::string name, invite;
    try {
        revet::json::Document doc(req.raw_body);
        name = durin::lower(doc.root().get("name", ""));
        invite = doc.root().get("invite", "");
    } catch (const std::exception&) {
        return web::api::error(web::status::bad_request, "bad_request");
    }

    auto h = resources::main_db<db::Write>();
    const auto who = durin::auth_session(h, req);
    if (!who) {
        if (!durin::invite_ok(h, invite)) return web::api::error(web::status::forbidden, "invite");
        if (!durin::valid_name(name)) return web::api::error(web::status::bad_request, "bad_name");
        if (durin::name_taken(h, name)) return web::api::error(web::status::conflict, "name_taken");
    }
    const auto opts = pk::begin_registration(h, who ? std::optional<std::string>(who->user_id) : std::nullopt, who ? who->name : name);
    if (!opts) return web::api::error(web::status::unauthorized, "unauthorized");

    revet::json::Writer w;
    w.object().key("challenge_id").value(opts->challenge_id).key("options").raw(opts->options_json).end();
    return web::Response{.body = std::move(w).str(), .content_type = "application/json"};
}

static auto route_guards() -> std::vector<web::Middleware> {
    return web::auth::limits::anonymous();
}
