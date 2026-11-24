#include <revet/csrf.hpp>
#include <revet/htmx.hpp>
#include <revet/sanitize.hpp>
#include <revet/web.hpp>
#include "durin.hpp"

// GET / on the auth host. With ?rd=<app address> and a live sign-in: straight back to the app with a
// one-time code. Otherwise the sign-in page (?invite= still opens the form; new links use #invite=), or, when
// signed in, the account page.
static auto render_get(const web::Request& req) -> web::Response {
    if (durin::request_host(req) != durin::settings().auth_host) {
        return web::Response{.body = "not found", .content_type = "text/plain", .status = web::status::not_found};
    }
    auto h = resources::main_db<db::Write>();
    const auto who = durin::auth_session(h, req);
    const auto rd = req.query.get("rd");
    const auto target = durin::parse_target(rd);

    const auto nonce_hash = req.query.get("n");
    if (who && target && durin::is_nonce_hash(nonce_hash)) {
        const auto code = durin::mint_code(h, who->parent_id, target->host, nonce_hash);
        return web::redirect("https://" + target->host + "/.durin/callback?code=" + code + "&rd=" + sanitize::url_encode(target->path),
                             web::status::found);
    }
    if (who) return layout_main(req, "Durin", account_page(req, who->user_id, who->name, who->parent_id));
    const auto for_host = target ? target->host : std::string();
    const auto invite = req.query.get("invite");
    return layout_main(req, "Sign in", sign_in_page(req, for_host, invite, durin::invite_ok(h, invite), durin::is_owner_link(h, invite)));
}
