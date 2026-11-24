#include <revet/log.hpp>
#include <revet/web.hpp>
#include "durin.hpp"

// POST /people/remove {user_id} (owners): delete someone's account, passkeys and sign-ins. Owners
// cannot be removed.
static auto render_post(const web::Request& req) -> web::Response {
    std::string owner_id;
    {
        auto h = resources::main_db<db::Write>();
        const auto who = durin::owner_session(h, req);
        if (!who) return web::Response{.body = "owners only", .content_type = "text/plain", .status = web::status::forbidden};
        owner_id = who->user_id;
        const auto target = req.form.get("user_id");
        const auto name = durin::name_of(h, target);
        if (durin::remove_person(h, target)) log::info("durin: {} removed {}", who->name, name);
    }
    return web::to_response(owner_panel(owner_id, ""));
}
