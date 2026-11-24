#include <revet/web.hpp>
#include "durin.hpp"

// GET /.durin/verify: forward auth for proxies that pass a redirect on to the browser (Caddy
// forward_auth, Traefik ForwardAuth). 200 + user header, or 302 to the sign-in page.
static auto render_get(const web::Request& req) -> web::Response {
    auto h = resources::main_db<db::Write>();
    return durin::verify(h, req, true);
}
