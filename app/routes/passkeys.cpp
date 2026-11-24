#include <revet/web.hpp>
#include "durin.hpp"

// GET /passkeys: the signed-in user's passkey list, refreshed after adding one.
static auto render_get(const web::Request& req) -> web::Response {
    std::optional<durin::Who> who;
    {
        auto h = resources::main_db<db::Write>();
        who = durin::auth_session(h, req);
    }
    if (!who) return web::Response{.body = "", .content_type = "text/html", .status = web::status::unauthorized};
    return web::to_response(passkey_list(who->user_id));
}
