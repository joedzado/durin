#include <revet/auth/passkeys.hpp>
#include <revet/htmx.hpp>
#include <revet/web.hpp>
#include "durin.hpp"

// POST /passkeys/remove {credential_id}: drop one of the signed-in user's passkeys (never the last).
static auto render_post(const web::Request& req) -> web::Response {
    namespace pk = web::auth::passkeys;
    std::optional<durin::Who> who;
    pk::RemoveResult result{};
    {
        auto h = resources::main_db<db::Write>();
        who = durin::auth_session(h, req);
        if (!who) return web::Response{.body = "sign in first", .content_type = "text/plain", .status = web::status::unauthorized};
        result = pk::remove_passkey(h, who->user_id, req.form.get("credential_id"));
    }
    auto resp = web::to_response(passkey_list(who->user_id));
    if (result == pk::RemoveResult::last_login_method) {
        resp.headers.data["HX-Trigger"] = R"({"durin-note":"Keep at least one passkey."})";
    }
    return resp;
}
