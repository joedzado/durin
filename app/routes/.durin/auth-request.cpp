#include <revet/web.hpp>
#include "durin.hpp"

// GET /.durin/auth-request: forward auth for nginx auth_request, which takes only 2xx, 401 and 403.
// 200 + user header, or 401 with the sign-in address in Location for `error_page 401 =302`.
static auto render_get(const web::Request& req) -> web::Response {
    auto h = resources::main_db<db::Write>();
    return durin::verify(h, req, false);
}
