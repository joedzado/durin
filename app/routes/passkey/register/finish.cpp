#include <revet/auth/limits.hpp>
#include <revet/auth/passkeys.hpp>
#include <revet/auth/users.hpp>
#include <revet/json.hpp>
#include <revet/log.hpp>
#include "durin.hpp"

// POST /passkey/register/finish: save the new passkey. A new account (invite or setup code again) is
// signed in; the setup code's account is the owner.
static auto render_post(const web::Request& req) -> web::Response {
    namespace pk = web::auth::passkeys;
    if (durin::request_host(req) != durin::settings().auth_host) return web::api::error(web::status::not_found, "not_found");
    std::string challenge_id, client_data, attestation, label, name, code, invite;
    try {
        revet::json::Document doc(req.raw_body);
        auto root = doc.root();
        challenge_id = root.get("challenge_id", "");
        client_data = root.get("client_data_json", "");
        attestation = root.get("attestation_object", "");
        label = root.get("label", "");
        name = durin::lower(root.get("name", ""));
        code = root.get("setup_code", "");
        invite = root.get("invite", "");
    } catch (const std::exception&) {
        return web::api::error(web::status::bad_request, "bad_request");
    }
    if (label.size() > 64) label.resize(64);

    auto h = resources::main_db<db::Write>();
    const auto who = durin::auth_session(h, req);
    const bool first = !who && durin::owner_count(h) == 0 && durin::setup_code_ok(code);
    if (!who && !first && !durin::invite_ok(h, invite)) return web::api::error(web::status::forbidden, invite.empty() ? "setup_code" : "invite");
    if (!who && !durin::valid_name(name)) return web::api::error(web::status::bad_request, "bad_name");

    // The framework refuses a challenge that was not issued to this caller: a signed-in user finishes only
    // their own add-passkey challenge, anyone else only a new-account one.
    const auto done = pk::finish_registration(h, challenge_id, client_data, attestation, label,
                                              who ? pk::Expect::user(who->user_id) : pk::Expect::new_account());
    if (!done) {
        log::warn("durin: passkey registration refused (kind {})", static_cast<int>(done.error().kind));
        const bool taken = done.error().kind == pk::Failure::Kind::credential_taken;
        return web::api::error(taken ? web::status::conflict : web::status::bad_request, taken ? "credential_taken" : "registration_failed");
    }
    if (who) {
        log::info("durin: {} added a passkey", who->name);
        return web::Response{.body = R"({"ok":true})", .content_type = "application/json"};
    }
    // Spend the invite (or re-check that there is still no owner) before keeping the account.
    const bool allowed = first ? durin::owner_count(h) == 0 : durin::take_invite(h, invite);
    if (!allowed || !durin::add_user(h, done->user_id, name, first)) {
        web::auth::delete_user(h, done->user_id);
        return allowed ? web::api::error(web::status::conflict, "name_taken") : web::api::error(web::status::forbidden, "invite");
    }
    log::info("durin: account {} created{}", name, first ? " (owner)" : " from an invite");
    const auto s = durin::sign_in(h, done->user_id, false);
    web::Response resp{.body = R"({"ok":true})", .content_type = "application/json"};
    durin::set_cookie(resp, s.token, false, 0);
    return resp;
}

static auto route_guards() -> std::vector<web::Middleware> {
    return web::auth::limits::anonymous();
}
