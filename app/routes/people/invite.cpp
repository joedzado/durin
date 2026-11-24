#include <revet/log.hpp>
#include <revet/web.hpp>
#include "durin.hpp"

// POST /people/invite (owners): a one-use link for one new account. The link is shown once.
static auto render_post(const web::Request& req) -> web::Response {
    std::string owner_id, link;
    {
        auto h = resources::main_db<db::Write>();
        const auto who = durin::owner_session(h, req);
        if (!who) return web::Response{.body = "owners only", .content_type = "text/plain", .status = web::status::forbidden};
        owner_id = who->user_id;
        link = durin::invite_url(durin::mint_invite(h, who->user_id));
        log::info("durin: {} made an invite", who->name);
    }
    return web::to_response(owner_panel(owner_id, link));
}
