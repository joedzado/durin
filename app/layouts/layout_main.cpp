#include <revet/csrf.hpp>
#include <revet/htmx.hpp>
#include <revet/web.hpp>
#include "routes.hpp"
#include "styles.hpp"

[[revet::export]]
web::Response layout_main(const web::Request& req, std::string_view title, html::Node inner) {
    return web::to_response(html::html_doc{
        html::head{
            html::meta{html::attr.charset("utf-8")},
            html::meta{html::attr.name("viewport"), html::attr.content("width=device-width,initial-scale=1")},
            html::meta{html::attr.name("robots"), html::attr.content("noindex")},
            html::title{std::string(title)},
            html::collect_styles(),
            htmx::script_tag(),
        },
        html::body{web::csrf::htmx_headers(req), html::main_el{styles::page, inner}}});
}
