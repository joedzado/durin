// Unit tests for Durin's core (src/durin.hpp) on a throwaway SQLite database. The browser test in
// tests/e2e covers the pages and the proxy handoff; these cover the rules.
#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <cstdio>
#include <cstdlib>
#include <revet/auth/passkeys.hpp>
#include <revet/auth/tokens.hpp>
#include <revet/auth/users.hpp>
#include <revet/db/sqlite.hpp>

#include "durin.hpp"

namespace {

using W = db::sqlite::Handle<db::Write>;

// The environment is read once, on first use: set it before any test runs.
[[maybe_unused]] const int env_ready = [] {
    setenv("DURIN_AUTH_HOST", "auth.example.test", 1);
    return 0;
}();

auto settings() -> durin::Settings {
    durin::Settings s;
    s.auth_host = "auth.example.test";
    s.suffix = "example.test";
    return s;
}

struct Fixture {
    std::string path;
    db::sqlite::Pool pool;
    static auto unique_path() -> std::string {
        static std::atomic<int> seq{0};
        const auto p = "/tmp/durin_test_" + std::to_string(seq++) + ".db";
        for (const char* suffix : {"", "-wal", "-shm"}) std::remove((p + suffix).c_str());
        return p;
    }
    Fixture() : path(unique_path()), pool(path, 2) {
        W w(pool);
        web::auth::create_schema(w);
        web::auth::tokens::create_schema(w);
        web::auth::passkeys::create_schema(w);
        durin::create_schema(w);
    }
    ~Fixture() {
        for (const char* suffix : {"", "-wal", "-shm"}) std::remove((path + suffix).c_str());
    }
    Fixture(const Fixture&) = delete;
    auto operator=(const Fixture&) -> Fixture& = delete;
};

auto make_user(W& h, const std::string& name, bool owner) -> std::string {
    const auto id = web::auth::find_or_create_user(h, "test", name);
    REQUIRE(durin::add_user(h, id, name, owner));
    return id;
}

// A request as a trusted proxy on this machine would forward it.
auto proxied(const std::string& host, const std::string& uri, const std::string& token = "") -> web::Request {
    web::Request req;
    req.peer_ip = "127.0.0.1";
    req.headers.data["host"] = "127.0.0.1:3130";
    req.headers.data["x-forwarded-host"] = host;
    req.headers.data["x-forwarded-uri"] = uri;
    if (!token.empty()) req.cookies.data[std::string(durin::cookie_name)] = token;
    return req;
}

// A request as nginx's auth_request would send it.
auto asked_url(const std::string& url) -> web::Request {
    web::Request req;
    req.headers.data["host"] = "127.0.0.1:3130";
    req.headers.data["x-original-url"] = url;
    return req;
}

} // namespace

TEST_CASE("app hosts are DNS names under the suffix, never the auth host") {
    const auto s = settings();
    CHECK(durin::is_app_host("a.example.test", s));
    CHECK(durin::is_app_host("a.b-c.example.test", s));
    CHECK_FALSE(durin::is_app_host("auth.example.test", s));
    CHECK_FALSE(durin::is_app_host("example.test", s));
    CHECK_FALSE(durin::is_app_host(".example.test", s));
    CHECK_FALSE(durin::is_app_host("evil.com", s));
    CHECK_FALSE(durin::is_app_host("a.example.test.evil.com", s));
    CHECK_FALSE(durin::is_app_host("-a.example.test", s));
    CHECK_FALSE(durin::is_app_host("a..example.test", s));
    CHECK_FALSE(durin::is_app_host("A.example.test", s));
    CHECK_FALSE(durin::is_app_host("a b.example.test", s));
    CHECK_FALSE(durin::is_app_host("a:8443.example.test", s));
}

TEST_CASE("local paths keep the browser on its own host") {
    CHECK(durin::is_local_path("/"));
    CHECK(durin::is_local_path("/a/b?c=d"));
    CHECK_FALSE(durin::is_local_path(""));
    CHECK_FALSE(durin::is_local_path("a/b"));
    CHECK_FALSE(durin::is_local_path("//evil.com"));
    CHECK_FALSE(durin::is_local_path("/\\evil.com"));
    CHECK_FALSE(durin::is_local_path("/a\nb"));
    CHECK_FALSE(durin::is_local_path(std::string("/a") + char(0x7f)));
    CHECK_FALSE(durin::is_local_path("https://evil.com"));
}

TEST_CASE("a sign-in return address is an https app host or nothing") {
    const auto s = settings();
    const auto ok = durin::parse_target("https://a.example.test/p?q=1", s);
    REQUIRE(ok);
    CHECK(ok->host == "a.example.test");
    CHECK(ok->path == "/p?q=1");
    CHECK(durin::parse_target("https://a.example.test", s)->path == "/");
    CHECK(durin::parse_target("https://a.example.test:443/x", s)->host == "a.example.test");
    CHECK(durin::parse_target("https://A.EXAMPLE.TEST/x", s)->host == "a.example.test");

    for (const char* bad : {"http://a.example.test/", "https://auth.example.test/", "https://evil.com/", "https://a.example.test@evil.com/",
                            "https://a.example.test\\@evil.com/", "https://a.example.test:8443/", "https://a.example.test//evil.com",
                            "//a.example.test/", "javascript:alert(1)", "", "/relative", "https://example.test/"}) {
        CHECK_FALSE(durin::parse_target(bad, s));
    }
}

TEST_CASE("each forward-auth endpoint reads only its own headers") {
    auto req = proxied("a.example.test:8443", "/p?q=1");
    req.headers.data["x-original-url"] = "https://b.example.test:8443/other?x=1";
    CHECK(durin::original_forwarded(req).host == "a.example.test");
    CHECK(durin::original_forwarded(req).path == "/p?q=1");
    CHECK(durin::original_url(req).host == "b.example.test");
    CHECK(durin::original_url(req).path == "/other?x=1");
    CHECK(durin::request_host(req) == "127.0.0.1"); // pages and the callback go by Host alone

    req.headers.data["x-original-url"] = "https://b.example.test";
    CHECK(durin::original_url(req).path == "/");
    for (const char* bad : {"", "b.example.test/x", "https://b.example.test@evil.com/"}) {
        req.headers.data["x-original-url"] = bad;
        CHECK(durin::original_url(req).host.empty());
    }
}

TEST_CASE("names are lower-case labels that are safe as a header value") {
    CHECK(durin::valid_name("joe"));
    CHECK(durin::valid_name("a.b_c-d9"));
    CHECK_FALSE(durin::valid_name(""));
    CHECK_FALSE(durin::valid_name("Joe"));
    CHECK_FALSE(durin::valid_name("a b"));
    CHECK_FALSE(durin::valid_name("a\r\nx"));
    CHECK_FALSE(durin::valid_name(std::string(33, 'a')));
    CHECK(durin::valid_name(std::string(32, 'a')));
}

TEST_CASE("names are shown with capitals") {
    CHECK(durin::shown_name("ann") == "Ann");
    CHECK(durin::shown_name("mary-ann.o_neil") == "Mary-Ann.O_Neil");
    CHECK(durin::shown_name("2cool") == "2cool");
    CHECK(durin::shown_name("").empty());
}

TEST_CASE("a sign-in ends after idle time, after the maximum, and not at all for others' hosts") {
    Fixture f;
    W h(f.pool);
    const auto s = settings();
    const auto uid = make_user(h, "ann", true);
    const long long t = 1'000'000;

    const auto in = durin::sign_in(h, uid, false, s, t);
    REQUIRE(durin::check(h, in.token, "auth.example.test", s, t + 10));
    CHECK_FALSE(durin::check(h, in.token, "a.example.test", s, t + 10)); // a cookie is for one host
    CHECK_FALSE(durin::check(h, "nonsense", "auth.example.test", s, t + 10));
    CHECK_FALSE(durin::check(h, "", "auth.example.test", s, t + 10));

    // Activity keeps it alive; silence does not.
    REQUIRE(durin::check(h, in.token, "auth.example.test", s, t + 250));
    REQUIRE(durin::check(h, in.token, "auth.example.test", s, t + 500));
    CHECK_FALSE(durin::check(h, in.token, "auth.example.test", s, t + 500 + s.idle_seconds + 1));

    const auto busy = durin::sign_in(h, uid, false, s, t);
    long long at = t;
    while (at + 200 < t + s.max_seconds) {
        at += 200;
        REQUIRE(durin::check(h, busy.token, "auth.example.test", s, at));
    }
    CHECK_FALSE(durin::check(h, busy.token, "auth.example.test", s, t + s.max_seconds + 1));

    const auto kept = durin::sign_in(h, uid, true, s, t);
    CHECK(durin::check(h, kept.token, "auth.example.test", s, t + 3 * 86400));
    CHECK_FALSE(durin::check(h, kept.token, "auth.example.test", s, t + s.remember_seconds + 1));
}

TEST_CASE("a one-time code opens one host once, in one browser, then its session follows the sign-in") {
    Fixture h0;
    W h(h0.pool);
    const auto s = settings();
    const auto uid = make_user(h, "ann", true);
    const long long t = 2'000'000;
    const auto in = durin::sign_in(h, uid, false, s, t);
    const std::string nonce = "this-browsers-nonce";
    const auto bound = durin::hash(nonce);

    const auto code = durin::mint_code(h, in.session_id, "a.example.test", bound, s, t);
    const auto got = durin::redeem_code(h, code, "a.example.test", nonce, s, t + 5);
    REQUIRE(got);
    CHECK(durin::check(h, got->started.token, "a.example.test", s, t + 6));
    CHECK_FALSE(durin::check(h, got->started.token, "auth.example.test", s, t + 6)); // not valid on the auth host
    CHECK_FALSE(durin::check(h, got->started.token, "b.example.test", s, t + 6));
    CHECK_FALSE(durin::redeem_code(h, code, "a.example.test", nonce, s, t + 7)); // single use

    const auto wrong = durin::mint_code(h, in.session_id, "a.example.test", bound, s, t);
    CHECK_FALSE(durin::redeem_code(h, wrong, "b.example.test", nonce, s, t + 1)); // bound to its host
    CHECK_FALSE(durin::redeem_code(h, wrong, "a.example.test", nonce, s, t + 2)); // and spent by the attempt

    // A code made for someone else's browser signs nobody else in, however it got there.
    const auto theirs = durin::mint_code(h, in.session_id, "a.example.test", durin::hash("attackers-nonce"), s, t);
    CHECK_FALSE(durin::redeem_code(h, theirs, "a.example.test", nonce, s, t + 1));
    const auto nothing = durin::mint_code(h, in.session_id, "a.example.test", bound, s, t);
    CHECK_FALSE(durin::redeem_code(h, nothing, "a.example.test", "", s, t + 1)); // a browser with no nonce cookie
    const auto spent = durin::mint_code(h, in.session_id, "a.example.test", bound, s, t);
    CHECK_FALSE(durin::redeem_code(h, spent, "a.example.test", "guess", s, t + 1));
    CHECK_FALSE(durin::redeem_code(h, spent, "a.example.test", nonce, s, t + 2)); // the wrong try spent it
    const auto unbound = durin::mint_code(h, in.session_id, "a.example.test", "", s, t);
    CHECK_FALSE(durin::redeem_code(h, unbound, "a.example.test", nonce, s, t + 1));

    const auto late = durin::mint_code(h, in.session_id, "a.example.test", bound, s, t);
    CHECK_FALSE(durin::redeem_code(h, late, "a.example.test", nonce, s, t + s.code_seconds + 1));
    CHECK_FALSE(durin::redeem_code(h, "", "a.example.test", nonce, s, t));
    CHECK_FALSE(durin::redeem_code(h, "made-up", "a.example.test", nonce, s, t));

    const auto hosts = durin::hosts_of(h, in.session_id);
    REQUIRE(hosts.size() == 1);
    CHECK(hosts[0].host == "a.example.test");

    durin::sign_out(h, in.session_id, t + 20);
    CHECK_FALSE(durin::check(h, got->started.token, "a.example.test", s, t + 21));
    CHECK_FALSE(durin::check(h, in.token, "auth.example.test", s, t + 21));
    const auto dead = durin::mint_code(h, in.session_id, "a.example.test", bound, s, t + 22);
    CHECK_FALSE(durin::redeem_code(h, dead, "a.example.test", nonce, s, t + 23)); // nothing to open under a signed-out sign-in
}

TEST_CASE("a nonce hash is 64 lower-case hex digits") {
    CHECK(durin::is_nonce_hash(durin::hash("x")));
    CHECK_FALSE(durin::is_nonce_hash(""));
    CHECK_FALSE(durin::is_nonce_hash(std::string(63, 'a')));
    CHECK_FALSE(durin::is_nonce_hash(std::string(65, 'a')));
    CHECK_FALSE(durin::is_nonce_hash(std::string(64, 'A')));
    CHECK_FALSE(durin::is_nonce_hash(std::string(63, 'a') + "g"));
}

TEST_CASE("signing out everywhere ends every sign-in of that user only") {
    Fixture f;
    W h(f.pool);
    const auto s = settings();
    const auto ann = make_user(h, "ann", true);
    const auto bob = make_user(h, "bob", false);
    const long long t = 3'000'000;
    const auto a1 = durin::sign_in(h, ann, true, s, t);
    const auto a2 = durin::sign_in(h, ann, true, s, t);
    const auto b1 = durin::sign_in(h, bob, true, s, t);

    durin::sign_out_everywhere(h, ann, t + 1);
    CHECK_FALSE(durin::check(h, a1.token, "auth.example.test", s, t + 2));
    CHECK_FALSE(durin::check(h, a2.token, "auth.example.test", s, t + 2));
    CHECK(durin::check(h, b1.token, "auth.example.test", s, t + 2));
}

TEST_CASE("an invite makes one account, once, for a week, and is stored hashed") {
    Fixture f;
    W h(f.pool);
    const auto s = settings();
    const auto owner = make_user(h, "ann", true);
    const long long t = 4'000'000;

    const auto code = durin::mint_invite(h, owner, s, t);
    CHECK(durin::invite_ok(h, code, t + 1));
    CHECK(h.scalar<long long>("SELECT COUNT(*) FROM durin_invites WHERE code_hash = ?", code).value_or(-1) == 0);
    CHECK(durin::open_invites(h, t + 1).size() == 1);
    CHECK(durin::take_invite(h, code, t + 2) == durin::Link::member);
    CHECK_FALSE(durin::take_invite(h, code, t + 3));
    CHECK_FALSE(durin::invite_ok(h, code, t + 3));

    const auto old = durin::mint_invite(h, owner, s, t);
    CHECK(durin::invite_ok(h, old, t + s.invite_seconds - 1));
    CHECK_FALSE(durin::invite_ok(h, old, t + s.invite_seconds + 1));
    CHECK_FALSE(durin::take_invite(h, old, t + s.invite_seconds + 1));

    const auto cancelled = durin::mint_invite(h, owner, s, t);
    const auto open = durin::open_invites(h, t + 1);
    REQUIRE_FALSE(open.empty());
    for (const auto& i : open) durin::revoke_invite(h, i.id);
    CHECK_FALSE(durin::invite_ok(h, cancelled, t + 1));

    CHECK_FALSE(durin::invite_ok(h, "", t));
    CHECK_FALSE(durin::invite_ok(h, "guess", t));
    CHECK_FALSE(durin::invite_ok(h, std::string(200, 'a'), t));
}

TEST_CASE("owners are counted, listed first, and cannot be removed; anyone else can") {
    Fixture f;
    W h(f.pool);
    const auto s = settings();
    CHECK(durin::owner_count(h) == 0);
    const auto bob = make_user(h, "bob", false);
    CHECK(durin::owner_count(h) == 0); // an ordinary account is not an owner
    const auto ann = make_user(h, "ann", true);
    CHECK(durin::owner_count(h) == 1);
    CHECK(durin::is_owner(h, ann));
    CHECK_FALSE(durin::is_owner(h, bob));
    CHECK(durin::name_taken(h, "bob"));
    CHECK_FALSE(durin::add_user(h, bob, "bob", false)); // a name is used once

    const auto people = durin::people(h);
    REQUIRE(people.size() == 2);
    CHECK(people[0].name == "ann");
    CHECK(people[0].owner);

    const long long t = 5'000'000;
    const auto in = durin::sign_in(h, bob, true, s, t);
    const auto code = durin::mint_invite(h, bob, s, t);
    CHECK_FALSE(durin::remove_person(h, ann, t));
    CHECK(durin::remove_person(h, bob, t + 1));
    CHECK_FALSE(durin::check(h, in.token, "auth.example.test", s, t + 2));
    CHECK(durin::name_of(h, bob).empty());
    CHECK_FALSE(durin::invite_ok(h, code, t + 2)); // a removed person's invites go with them
    CHECK(durin::user_count(h) == 1);
    CHECK_FALSE(durin::remove_person(h, "no-such-user", t));
}

TEST_CASE("forward auth: sign-in redirect, 401 for nginx, the user header, and nothing for other hosts") {
    Fixture f;
    W h(f.pool);
    const auto uid = make_user(h, "ann", true);

    const auto none = durin::verify(h, proxied("a.example.test", "/p?q=1"), true);
    CHECK(none.status.code == 302);
    CHECK(none.location == "https://a.example.test/.durin/start?rd=%2Fp%3Fq%3D1"); // sign-in starts on the app host

    const auto no = durin::verify(h, asked_url("https://a.example.test/p"), false);
    CHECK(no.status.code == 401);
    CHECK(no.headers.get("Location") == "https://a.example.test/.durin/start?rd=%2Fp");

    const auto sneaky = durin::verify(h, proxied("a.example.test", "//evil.com"), true);
    CHECK(sneaky.location == "https://a.example.test/.durin/start?rd=%2F"); // a bad path becomes "/"

    CHECK(durin::verify(h, proxied("evil.com", "/"), true).status.code == 403);
    CHECK(durin::verify(h, proxied("auth.example.test", "/"), true).status.code == 403); // the auth host is never gated
    CHECK(durin::verify(h, proxied("example.test", "/"), true).status.code == 403);

    // The other style's headers do not count, and no header means no host: refused.
    CHECK(durin::verify(h, proxied("a.example.test", "/"), false).status.code == 403);
    CHECK(durin::verify(h, asked_url("https://a.example.test/"), true).status.code == 403);

    const auto in = durin::sign_in(h, uid, false);
    const auto code = durin::mint_code(h, in.session_id, "a.example.test", durin::hash("n"));
    const auto got = durin::redeem_code(h, code, "a.example.test", "n");
    REQUIRE(got);
    const auto ok = durin::verify(h, proxied("a.example.test", "/p", got->started.token), true);
    CHECK(ok.status.code == 200);
    CHECK(ok.headers.get("Remote-User") == "ann");
    CHECK(durin::verify(h, proxied("b.example.test", "/p", got->started.token), true).status.code == 302); // a cookie is for one host
    CHECK(durin::verify(h, proxied("a.example.test", "/p", in.token), true).status.code == 302);            // the auth-host cookie is not an app cookie

    durin::sign_out(h, in.session_id);
    CHECK(durin::verify(h, proxied("a.example.test", "/p", got->started.token), true).status.code == 302);
}

TEST_CASE("an owner link makes an owner, once, for an hour, and only the newest works") {
    Fixture f;
    W h(f.pool);
    const auto s = settings();
    const long long t = 6'000'000;
    const auto old = durin::mint_owner_link(h, s, t);
    const auto code = durin::mint_owner_link(h, s, t);
    CHECK_FALSE(durin::invite_ok(h, old, t + 1));
    CHECK(durin::invite_ok(h, code, t + 1));
    CHECK(durin::is_owner_link(h, code, t + 1));
    CHECK(durin::open_invites(h, t + 1).empty()); // not listed for anyone on the web
    CHECK(durin::take_invite(h, code, t + 2) == durin::Link::owner);
    CHECK_FALSE(durin::take_invite(h, code, t + 3));
    const auto late = durin::mint_owner_link(h, s, t);
    CHECK_FALSE(durin::take_invite(h, late, t + s.owner_link_seconds + 1));

    const auto ann = make_user(h, "ann", true); // an owner's own invites never make owners
    const auto invite = durin::mint_invite(h, ann, s, t);
    CHECK_FALSE(durin::is_owner_link(h, invite, t + 1));
    CHECK(durin::take_invite(h, invite, t + 1) == durin::Link::member);
}
