// Durin's entry point: serve, or `owner` to print a link that makes an owner account.
#include <print>
#include <string_view>
#include <vector>

#include <revet/log.hpp>
#include <revet/web.hpp>
#include "durin.hpp"
#include "resources.hpp"

namespace routes {
void setup(std::vector<web::Route>& out);
}
void site_init();

auto main(int argc, char** argv) -> int {
    const bool owner = argc > 1 && std::string_view(argv[1]) == "owner";
    try {
        web::init(argc, argv);
        web::log::set_level(owner ? web::log::Level::WARN : web::log::Level::INFO);
        if (!owner) web::log::init_from_env();
        site_init();
        if (owner) {
            auto h = resources::main_db<db::Write>();
            std::println("{}", durin::auth_url("/?invite=" + durin::mint_owner_link(h)));
            return 0;
        }
        std::vector<web::Route> all_routes;
        routes::setup(all_routes);
        web::listen(all_routes);
    } catch (const web::StartupError& e) {
        std::println(stderr, "{}", e.what());
        return e.exit_code;
    } catch (const std::exception& e) {
        std::println(stderr, "durin: {}", e.what());
        return 1;
    }
    return 0;
}
