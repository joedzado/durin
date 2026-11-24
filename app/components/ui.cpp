#include <chrono>
#include <format>
#include <revet/auth/passkeys.hpp>
#include <revet/csrf.hpp>
#include <revet/htmx.hpp>
#include <revet/web.hpp>
#include "durin.hpp"
#include "resources.hpp"
#include "routes.hpp"
#include "scripts.hpp"
#include "styles.hpp"

static constexpr html::id PASSKEY_LIST{"passkey-list"};
static constexpr html::id OWNER_PANEL{"owner-panel"};

static auto date_text(long long unix_seconds) -> std::string {
    if (unix_seconds <= 0) return "never";
    return std::format("{:%Y-%m-%d}", std::chrono::sys_seconds{std::chrono::seconds{unix_seconds}});
}

static auto status_line() -> html::Node {
    return html::p{html::attr.id("durin-status"), styles::status, html::attr("aria-live", "polite")};
}

// The user's passkeys, each with a Remove button. Swapped by id after adding and removing.
[[revet::export]]
html::Node passkey_list(std::string_view user_id) {
    auto db = resources::main_db();
    const auto passkeys = web::auth::passkeys::list_passkeys(db, user_id);
    return html::div{PASSKEY_LIST, styles::rows,
        html::list(passkeys, [](const auto& p) -> html::Node {
            return html::div{styles::row,
                html::div{styles::grow,
                    html::div{styles::row_name, p.label.empty() ? std::string("Passkey") : p.label},
                    html::div{styles::meta, "Added " + date_text(p.created_at) + " · last used " + date_text(p.last_used_at) +
                                                (p.backup_state ? " · synced" : "")}},
                html::button{styles::btn, styles::btn_quiet, html::attr.type("button"), htmx::attr::post(urls::passkeys_remove),
                             htmx::attr::vals(R"({"credential_id":")" + p.credential_id + R"("})"), htmx::attr::target(PASSKEY_LIST),
                             htmx::attr::swap_outer_html(), "Remove"}};
        })};
}

static auto join_form(std::string_view invite, bool live, bool owner) -> html::Node {
    if (!invite.empty() && !live) return html::p{styles::meta, "This link was used, cancelled or has expired. Ask for a new one."};
    // Hidden until a fragment invite arrives. A ?invite= link from an older Durin opens it here.
    const bool open = !invite.empty() && live;
    return html::div{html::attr.id("join-block"), styles::setup, open ? html::Node{} : html::attr.hidden(),
        html::h2{styles::subheading, owner ? "Make the owner account" : "You're invited: make an account"},
        html::label{styles::field, "Name", html::input{html::attr.type("text"), html::attr.id("join-name"), html::attr.autocomplete("username")}},
        html::input{html::attr.type("hidden"), html::attr.id("invite-code"), html::attr.value(std::string(invite))},
        html::button{styles::btn, html::attr.type("button"), html::attr("data-durin", "join"), "Create a passkey"}};
}

// Signed out. `for_host` names the app that sent the visitor here, if any. `invite`: a ?invite= code,
// `live` or not, and whether it makes an `owner`.
[[revet::export]]
html::Node sign_in_page(const web::Request& req, std::string_view for_host, std::string_view invite, bool live, bool owner) {
    return html::div{styles::card, html::attr("data-csrf", web::csrf::token_from(req)),
        html::h1{styles::heading, "Speak, friend, and enter"},
        for_host.empty() ? html::Node{} : html::Node(html::p{styles::meta, "Sign in to continue to ", html::strong{std::string(for_host)}, "."}),
        html::button{styles::btn, styles::btn_main, html::attr.type("button"), html::attr("data-durin", "signin"), "Sign in with a passkey"},
        html::label{styles::check, html::input{html::attr.type("checkbox"), html::attr.id("remember")}, " Remember me for a month"},
        status_line(),
        join_form(invite, live, owner),
        scripts::durin_tag()};
}

// Owners only: who has an account, open invite links, and a button for a new one. `new_link` is shown
// once, right after it is made.
[[revet::export]]
html::Node owner_panel(std::string_view owner_id, std::string_view new_link) {
    auto db = resources::main_db();
    const auto everyone = durin::people(db);
    const auto invites = durin::open_invites(db);
    const std::string me(owner_id);
    return html::div{OWNER_PANEL, styles::rows,
        html::h2{styles::subheading, "People"},
        html::list(everyone, [&](const durin::Person& p) -> html::Node {
            return html::div{styles::row,
                html::div{styles::grow,
                    html::div{styles::row_name, durin::shown_name(p.name), p.owner ? " · owner" : ""},
                    html::div{styles::meta, std::format("{} passkey{} · joined {}", p.passkeys, p.passkeys == 1 ? "" : "s", date_text(p.created_at))}},
                p.owner || p.user_id == me ? html::Node{}
                    : html::Node(html::button{styles::btn, styles::btn_quiet, html::attr.type("button"), htmx::attr::post(urls::people_remove),
                          htmx::attr::vals(R"({"user_id":")" + p.user_id + R"("})"), htmx::attr::target(OWNER_PANEL), htmx::attr::swap_outer_html(),
                          htmx::attr::confirm("Remove " + durin::shown_name(p.name) + "? Their passkeys and sign-ins end now."), "Remove"})};
        }),
        html::h2{styles::subheading, "Invite links"},
        new_link.empty() ? html::Node{}
            : html::Node(html::div{styles::setup,
                  html::p{styles::meta, "Send this link to one person. It makes one account and works for 7 days. It won't be shown again."},
                  html::input{styles::link_box, html::attr.type("text"), html::attr.id("invite-link"), html::attr("readonly", "readonly"),
                              html::attr.value(std::string(new_link))},
                  html::button{styles::btn, html::attr.type("button"), html::attr("data-durin", "copy"), "Copy link"}}),
        invites.empty() ? html::Node(html::p{styles::meta, "No unused links."})
            : html::Node(html::div{styles::rows, html::list(invites, [](const durin::Invite& i) -> html::Node {
                  return html::div{styles::row,
                      html::div{styles::grow, html::div{styles::meta, "Made " + date_text(i.created_at) + (i.by.empty() ? "" : " by " + durin::shown_name(i.by)) +
                                                                          " · expires " + date_text(i.expires_at)}},
                      html::button{styles::btn, styles::btn_quiet, html::attr.type("button"), htmx::attr::post(urls::people_revoke),
                                   htmx::attr::vals(R"({"id":")" + i.id + R"("})"), htmx::attr::target(OWNER_PANEL),
                                   htmx::attr::swap_outer_html(), "Cancel"}};
              })}),
        html::div{styles::actions,
            html::button{styles::btn, html::attr.type("button"), htmx::attr::post(urls::people_invite), htmx::attr::target(OWNER_PANEL),
                         htmx::attr::swap_outer_html(), "New invite link"}}};
}

// Signed in at the auth host.
[[revet::export]]
html::Node account_page(const web::Request& req, std::string_view user_id, std::string_view name, std::string_view parent_id) {
    auto db = resources::main_db();
    const auto hosts = durin::hosts_of(db, parent_id);
    return html::div{styles::card, html::attr("data-csrf", web::csrf::token_from(req)),
        html::h1{styles::heading, "Signed in as ", durin::shown_name(name)},
        html::h2{styles::subheading, "Apps opened with this sign-in"},
        hosts.empty() ? html::Node(html::p{styles::meta, "None yet."})
                      : html::Node(html::div{styles::rows, html::list(hosts, [](const durin::HostSession& s) -> html::Node {
                            return html::a{styles::row, styles::row_link, html::attr.href("https://" + s.host + "/"),
                                           html::span{styles::row_name, s.host}, html::span{styles::meta, date_text(s.created_at)}};
                        })}),
        html::h2{styles::subheading, "Your passkeys"},
        passkey_list(user_id),
        html::div{styles::actions,
            html::button{styles::btn, html::attr.type("button"), html::attr("data-durin", "add"), "Add a passkey"},
            html::form{styles::inline_form, html::attr.method("post"), html::attr.action(std::string(urls::logout)), web::csrf::field(req),
                       html::submit{styles::btn, "Sign out"}},
            html::form{styles::inline_form, html::attr.method("post"), html::attr.action(std::string(urls::logout)), web::csrf::field(req),
                       html::input{html::attr.type("hidden"), html::attr.name("everywhere"), html::attr.value("1")},
                       html::submit{styles::btn, styles::btn_quiet, "Sign out everywhere"}}},
        durin::is_owner(db, user_id) ? owner_panel(user_id, "") : html::Node{},
        status_line(),
        scripts::durin_tag()};
}
