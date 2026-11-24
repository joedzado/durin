#include <revet/web.hpp>
#include "durin.hpp"

// POST /people/revoke {id} (owners): cancel an unused invite link.
static auto render_post(const web::Request& req) -> web::Response {
    std::string owner_id;
    {
        auto h = resources::main_db<db::Write>();
        const auto who = durin::owner_session(h, req);
        if (!who) return web::Response{.body = "owners only", .content_type = "text/plain", .status = web::status::forbidden};
        owner_id = who->user_id;
        durin::revoke_invite(h, req.form.get("id"));
    }
    return web::to_response(owner_panel(owner_id, ""));
}
