#pragma once

// Durin: one passkey sign-in at the auth host (e.g. auth.example.com) for every app host under the
// suffix (*.example.com), behind any reverse proxy with forward auth.
//
// There is no shared cookie (browsers set none on a bare public suffix, and host-only cookies leak
// less). Instead:
//   1. The proxy's forward auth asks /.durin/verify (302 on failure: Caddy, Traefik) or
//      /.durin/auth-request (401 + Location: nginx auth_request). No valid cookie for that host:
//      off to the auth host.
//   2. The auth host, once signed in, mints a one-time code bound to the app host and sends the browser
//      to <app host>/.durin/callback?code=... (the proxy routes /.durin/* on every host to Durin).
//   3. The callback swaps the code for a host-only cookie on the app host.
// Every cookie names a server-side session row. App-host sessions hang off the sign-in session, so
// signing out at the auth host ends all of them at once.
//
// Passkeys, users and rate limits come from Revet's framework auth (web::auth).

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>

#include <sodium.h>

#include <revet/auth/users.hpp>
#include <revet/crypto.hpp>
#include <revet/sanitize.hpp>
#include <revet/web.hpp>
#include <revet/webauthn.hpp>

namespace durin {

struct Settings {
    std::string auth_host;                // DURIN_AUTH_HOST (required): where sign-in happens, the passkey RP ID
    std::string suffix;                   // DURIN_SUFFIX: app hosts are <name>.<suffix>; default: the auth host
                                          // without its first label
    std::string user_header = "Remote-User"; // DURIN_USER_HEADER: the header verify answers with the account name
    long long idle_seconds = 5 * 60;      // DURIN_IDLE_SECONDS: unremembered sign-in ends after this much quiet
    long long max_seconds = 12 * 3600;    // DURIN_MAX_SECONDS: ... and after this long in any case
    long long remember_seconds = 30 * 86400; // DURIN_REMEMBER_SECONDS: "remember me" lasts this long
    long long code_seconds = 60;          // one-time code lifetime
    long long invite_seconds = 7 * 86400; // an invite link lasts this long, for one account
    long long owner_link_seconds = 3600;  // an owner link lasts this long
    long long touch_seconds = 15;         // write last_seen at most this often
};

inline constexpr std::string_view cookie_name = "__Host-durin";
// Set on an app host when a sign-in starts there, and required to finish it there: a hand-off code
// made in someone else's browser does not sign this browser in.
inline constexpr std::string_view nonce_cookie_name = "__Host-durin-nonce";

inline auto settings() -> const Settings& {
    static const Settings s = [] {
        Settings c;
        auto text = [](const char* name, std::string& out) {
            if (const char* v = std::getenv(name); v != nullptr && *v != '\0') out = v;
        };
        auto number = [](const char* name, long long& out) {
            if (const char* v = std::getenv(name); v != nullptr) {
                char* end = nullptr;
                const long long n = std::strtoll(v, &end, 10);
                if (end != v && *end == '\0' && n > 0) out = n;
            }
        };
        text("DURIN_AUTH_HOST", c.auth_host);
        text("DURIN_SUFFIX", c.suffix);
        text("DURIN_USER_HEADER", c.user_header);
        for (auto* v : {&c.auth_host, &c.suffix}) {
            std::ranges::transform(*v, v->begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        }
        if (c.suffix.empty()) {
            if (const auto dot = c.auth_host.find('.'); dot != std::string::npos) c.suffix = c.auth_host.substr(dot + 1);
        }
        number("DURIN_IDLE_SECONDS", c.idle_seconds);
        number("DURIN_MAX_SECONDS", c.max_seconds);
        number("DURIN_REMEMBER_SECONDS", c.remember_seconds);
        return c;
    }();
    return s;
}

// ── hosts and return addresses ───────────────────────────────────────────────

inline auto lower(std::string_view s) -> std::string {
    std::string out(s);
    std::ranges::transform(out, out.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

inline auto strip_port(std::string h) -> std::string {
    if (const auto comma = h.find(','); comma != std::string::npos) h.resize(comma);
    if (const auto colon = h.rfind(':'); colon != std::string::npos && h.find(']') == std::string::npos) h.resize(colon);
    return lower(h);
}

// The host the browser asked for, without a port. Proxies pass Host through (docs/proxies.md).
inline auto request_host(const web::Request& req) -> std::string {
    return strip_port(req.headers.get("host"));
}

struct Original {
    std::string host; // without a port
    std::string path; // path and query as sent; callers check it with is_local_path
};

// The browser's request that a forward-auth request asks about. Each endpoint reads only its own headers,
// which its proxies always overwrite, so a client cannot slip in the other style's. No trusted-proxy check
// is needed: the answer goes to whoever asked, so forging these headers gains nothing.

// /.durin/verify (Caddy, Traefik, Envoy): X-Forwarded-Host and X-Forwarded-Uri.
inline auto original_forwarded(const web::Request& req) -> Original {
    const auto h = req.headers.get("x-forwarded-host");
    return {h.empty() ? request_host(req) : strip_port(h), req.headers.get("x-forwarded-uri")};
}

// /.durin/auth-request (nginx, HAProxy): X-Original-URL: <scheme>://<host><path>. Anything else: no host.
inline auto original_url(const web::Request& req) -> Original {
    const std::string url = req.headers.get("x-original-url");
    const auto sep = url.find("://");
    if (sep == std::string::npos) return {};
    const auto rest = std::string_view(url).substr(sep + 3);
    const auto slash = rest.find('/');
    const auto authority = rest.substr(0, slash);
    if (authority.contains('@')) return {};
    return {strip_port(std::string(authority)), slash == std::string_view::npos ? "/" : std::string(rest.substr(slash))};
}

// <label>(.<label>)*.<suffix>, DNS characters only, and not the auth host.
inline auto is_app_host(std::string_view host, const Settings& s = settings()) -> bool {
    const std::string tail = "." + s.suffix;
    if (host.size() <= tail.size() || host.size() > 253 || !host.ends_with(tail) || host == s.auth_host) return false;
    const auto name = host.substr(0, host.size() - tail.size());
    if (name.front() == '.' || name.back() == '.' || name.front() == '-' || name.contains("..")) return false;
    return std::ranges::all_of(name, [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.'; });
}

// A path the callback may send the browser to on its own host: starts with one '/', no scheme-relative
// "//" or "/\", no control characters.
inline auto is_local_path(std::string_view p) -> bool {
    if (p.empty() || p.front() != '/' || p.size() > 4096) return false;
    if (p.size() > 1 && (p[1] == '/' || p[1] == '\\')) return false;
    return std::ranges::none_of(p, [](char c) { return static_cast<unsigned char>(c) < 0x20 || c == 0x7f; });
}

struct Target {
    std::string host;
    std::string path; // path and query, starts with '/'
};

// Where a sign-in should return to: https://<app host>[:443]<path>. Anything else (other schemes,
// other suffixes, the auth host itself, userinfo, odd paths) is refused, so this is no open redirect.
inline auto parse_target(std::string_view url, const Settings& s = settings()) -> std::optional<Target> {
    constexpr std::string_view scheme = "https://";
    if (!url.starts_with(scheme) || url.size() > 4096) return std::nullopt;
    auto rest = url.substr(scheme.size());
    const auto slash = rest.find('/');
    auto authority = rest.substr(0, slash);
    std::string path = slash == std::string_view::npos ? "/" : std::string(rest.substr(slash));
    if (authority.contains('@') || authority.contains('\\')) return std::nullopt;
    if (authority.ends_with(":443")) authority.remove_suffix(4);
    auto host = lower(authority);
    if (!is_app_host(host, s) || !is_local_path(path)) return std::nullopt;
    return Target{std::move(host), std::move(path)};
}

// ── secrets ──────────────────────────────────────────────────────────────────

inline auto random_token() -> std::string {
    web::crypto::init();
    std::array<unsigned char, 32> raw{};
    randombytes_buf(raw.data(), raw.size());
    return web::webauthn::base64url_encode(std::string_view(reinterpret_cast<const char*>(raw.data()), raw.size()));
}

inline auto random_id() -> std::string {
    web::crypto::init();
    std::array<unsigned char, 16> raw{};
    randombytes_buf(raw.data(), raw.size());
    std::string hex(raw.size() * 2 + 1, '\0');
    sodium_bin2hex(hex.data(), hex.size(), raw.data(), raw.size());
    hex.pop_back();
    return hex;
}

inline auto hash(std::string_view token) -> std::string {
    web::crypto::init();
    std::array<unsigned char, crypto_hash_sha256_BYTES> d{};
    crypto_hash_sha256(d.data(), reinterpret_cast<const unsigned char*>(token.data()), token.size());
    std::string hex(d.size() * 2 + 1, '\0');
    sodium_bin2hex(hex.data(), hex.size(), d.data(), d.size());
    hex.pop_back();
    return hex;
}

inline auto now() -> long long {
    return web::auth::detail::now();
}

// ── schema ───────────────────────────────────────────────────────────────────

// After web::auth::create_schema and passkeys::create_schema.
template<typename H>
void create_schema(H& h) {
    h.exec("CREATE TABLE IF NOT EXISTS durin_users ("
           " user_id TEXT PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,"
           " name TEXT NOT NULL UNIQUE,"
           " owner SMALLINT NOT NULL DEFAULT 0,"
           " created_at BIGINT NOT NULL)");
    if (h.template scalar<long long>("SELECT COUNT(*) FROM pragma_table_info('durin_users') WHERE name = 'owner'").value_or(0) == 0) {
        h.exec("ALTER TABLE durin_users ADD COLUMN owner SMALLINT NOT NULL DEFAULT 0");
    }
    // Links are short-lived, so a table from before owner links is simply replaced.
    if (h.template scalar<long long>("SELECT COUNT(*) FROM pragma_table_info('durin_invites') WHERE name = 'owner'").value_or(0) == 0) {
        h.exec("DROP TABLE IF EXISTS durin_invites");
    }
    // created_by NULL: an owner link made on the server's command line.
    h.exec("CREATE TABLE IF NOT EXISTS durin_invites ("
           " id TEXT PRIMARY KEY,"
           " code_hash TEXT NOT NULL UNIQUE,"
           " created_by TEXT REFERENCES auth_users(id) ON DELETE CASCADE,"
           " owner SMALLINT NOT NULL DEFAULT 0,"
           " created_at BIGINT NOT NULL,"
           " expires_at BIGINT NOT NULL)");
    // parent_id NULL: a sign-in at the auth host. Otherwise: an app host's session under that sign-in.
    h.exec("CREATE TABLE IF NOT EXISTS durin_sessions ("
           " id TEXT PRIMARY KEY,"
           " token_hash TEXT NOT NULL UNIQUE,"
           " user_id TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,"
           " host TEXT NOT NULL,"
           " parent_id TEXT REFERENCES durin_sessions(id) ON DELETE CASCADE,"
           " remember SMALLINT NOT NULL,"
           " created_at BIGINT NOT NULL,"
           " last_seen_at BIGINT NOT NULL,"
           " expires_at BIGINT NOT NULL,"
           " revoked_at BIGINT)");
    h.exec("CREATE INDEX IF NOT EXISTS durin_sessions_parent ON durin_sessions (parent_id)");
    h.exec("CREATE INDEX IF NOT EXISTS durin_sessions_user ON durin_sessions (user_id)");
    h.exec("CREATE TABLE IF NOT EXISTS durin_codes ("
           " code_hash TEXT PRIMARY KEY,"
           " parent_id TEXT NOT NULL REFERENCES durin_sessions(id) ON DELETE CASCADE,"
           " host TEXT NOT NULL,"
           " nonce_hash TEXT NOT NULL DEFAULT '',"
           " expires_at BIGINT NOT NULL)");
    if (h.template scalar<long long>("SELECT COUNT(*) FROM pragma_table_info('durin_codes') WHERE name = 'nonce_hash'").value_or(0) == 0) {
        h.exec("ALTER TABLE durin_codes ADD COLUMN nonce_hash TEXT NOT NULL DEFAULT ''");
    }
}

// ── users ────────────────────────────────────────────────────────────────────

template<typename H>
auto user_count(H& h) -> long long {
    return h.template scalar<long long>("SELECT COUNT(*) FROM durin_users").value_or(0);
}

template<typename H>
auto owner_count(H& h) -> long long {
    return h.template scalar<long long>("SELECT COUNT(*) FROM durin_users WHERE owner = 1").value_or(0);
}

template<typename H>
auto name_of(H& h, std::string_view user_id) -> std::string {
    return h.template scalar<std::string>("SELECT name FROM durin_users WHERE user_id = ?", std::string(user_id)).value_or("");
}

template<typename H>
auto name_taken(H& h, std::string_view name) -> bool {
    return h.template scalar<long long>("SELECT COUNT(*) FROM durin_users WHERE name = ?", std::string(name)).value_or(0) > 0;
}

// a-z, 0-9, '.', '_', '-'; 1 to 32 characters. It becomes the Remote-User header.
inline auto valid_name(std::string_view n) -> bool {
    return !n.empty() && n.size() <= 32 &&
           std::ranges::all_of(n, [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'; });
}

// How people see a name: "mary-ann" is "Mary-Ann". The stored name, which apps get, stays lower case.
inline auto shown_name(std::string_view n) -> std::string {
    std::string out(n);
    bool start = true;
    for (char& c : out) {
        if (start) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        start = c == '-' || c == '.' || c == '_';
    }
    return out;
}

template<typename H>
auto add_user(H& h, std::string_view user_id, std::string_view name, bool owner, long long t = now()) -> bool {
    if (name_taken(h, name)) return false;
    h.exec("INSERT INTO durin_users (user_id, name, owner, created_at) VALUES (?, ?, ?, ?)", std::string(user_id), std::string(name),
           owner ? 1 : 0, t);
    return true;
}

// ── sessions ─────────────────────────────────────────────────────────────────

struct Who {
    std::string user_id;
    std::string name;
    std::string session_id; // the row the cookie names
    std::string parent_id;  // the sign-in it belongs to (== session_id at the auth host)
    bool remember = false;
};

struct Started {
    std::string token; // cookie value
    std::string session_id;
};

// A sign-in at the auth host, after a passkey check.
template<typename H>
auto sign_in(H& h, std::string_view user_id, bool remember, const Settings& s = settings(), long long t = now()) -> Started {
    h.exec("DELETE FROM durin_sessions WHERE expires_at < ? OR revoked_at < ?", t - 86400, t - 86400);
    h.exec("DELETE FROM durin_codes WHERE expires_at < ?", t);
    const auto id = random_id();
    const auto token = random_token();
    const long long expires = t + (remember ? s.remember_seconds : s.max_seconds);
    h.exec("INSERT INTO durin_sessions (id, token_hash, user_id, host, parent_id, remember, created_at, last_seen_at, expires_at)"
           " VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?)",
           id, hash(token), std::string(user_id), s.auth_host, remember ? 1 : 0, t, t, expires);
    return {token, id};
}

// The session a cookie names, if it is for this host and its sign-in is still live. Keeps the
// sign-in's idle clock running.
template<typename H>
auto check(H& h, std::string_view token, std::string_view host, const Settings& s = settings(), long long t = now()) -> std::optional<Who> {
    if (token.empty() || token.size() > 128) return std::nullopt;
    const auto rows = h.template query_as<std::string, std::string, std::string, std::string, long long, long long, long long,
                                          std::optional<long long>, std::optional<long long>, long long>(
        "SELECT s.id, s.user_id, s.host, p.id, p.remember, p.last_seen_at, p.expires_at, p.revoked_at, s.revoked_at, s.expires_at"
        " FROM durin_sessions s JOIN durin_sessions p ON p.id = COALESCE(s.parent_id, s.id)"
        " WHERE s.token_hash = ? AND p.parent_id IS NULL",
        hash(token));
    if (rows.empty()) return std::nullopt;
    const auto& [sid, user_id, row_host, parent, remember, last_seen, expires, p_revoked, s_revoked, s_expires] = rows.front();
    if (row_host != host || p_revoked || s_revoked || t >= expires || t >= s_expires) return std::nullopt;
    if (remember == 0 && t - last_seen >= s.idle_seconds) return std::nullopt;
    if (t - last_seen >= s.touch_seconds) {
        h.exec("UPDATE durin_sessions SET last_seen_at = ? WHERE id = ?", t, parent);
    }
    return Who{user_id, name_of(h, user_id), sid, parent, remember != 0};
}

// The nonce hash a sign-in carries from the app host to the auth host: 64 lower-case hex digits.
inline auto is_nonce_hash(std::string_view n) -> bool {
    return n.size() == 64 && std::ranges::all_of(n, [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

// A one-time code that lets `host` open a session under the sign-in `parent_id`, for the browser
// that holds the nonce whose hash is `nonce_hash`.
template<typename H>
auto mint_code(H& h, std::string_view parent_id, std::string_view host, std::string_view nonce_hash, const Settings& s = settings(),
               long long t = now()) -> std::string {
    const auto code = random_token();
    h.exec("INSERT INTO durin_codes (code_hash, parent_id, host, nonce_hash, expires_at) VALUES (?, ?, ?, ?, ?)", hash(code),
           std::string(parent_id), std::string(host), std::string(nonce_hash), t + s.code_seconds);
    return code;
}

struct Redeemed {
    Started started;
    bool remember = false;
    long long expires_at = 0;
};

// Spend a code at `host`, by the browser holding `nonce`. Single use: it is gone whether or not it
// was for this host or this browser.
template<typename H>
auto redeem_code(H& h, std::string_view code, std::string_view host, std::string_view nonce, const Settings& s = settings(),
                 long long t = now()) -> std::optional<Redeemed> {
    if (code.empty() || code.size() > 128) return std::nullopt;
    web::auth::detail::Tx<H> tx(h);
    const auto rows = h.template query_as<std::string, std::string, std::string>(
        "DELETE FROM durin_codes WHERE code_hash = ? AND expires_at > ? RETURNING parent_id, host, nonce_hash", hash(code), t);
    if (rows.empty()) {
        tx.commit();
        return std::nullopt;
    }
    const auto& [parent, code_host, bound] = rows.front();
    const auto p = h.template query_as<std::string, long long, long long, long long, std::optional<long long>>(
        "SELECT user_id, remember, last_seen_at, expires_at, revoked_at FROM durin_sessions WHERE id = ? AND parent_id IS NULL", parent);
    if (code_host != host || p.empty() || nonce.empty() || nonce.size() > 128 || !web::crypto::secure_eq(hash(nonce), bound)) {
        tx.commit();
        return std::nullopt;
    }
    const auto& [user_id, remember, last_seen, expires, revoked] = p.front();
    if (revoked || t >= expires || (remember == 0 && t - last_seen >= s.idle_seconds)) {
        tx.commit();
        return std::nullopt;
    }
    const auto id = random_id();
    const auto token = random_token();
    h.exec("INSERT INTO durin_sessions (id, token_hash, user_id, host, parent_id, remember, created_at, last_seen_at, expires_at)"
           " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
           id, hash(token), user_id, std::string(host), parent, remember, t, t, expires);
    tx.commit();
    return Redeemed{{token, id}, remember != 0, expires};
}

// End a sign-in and every app-host session under it.
template<typename H>
auto sign_out(H& h, std::string_view parent_id, long long t = now()) -> void {
    h.exec("UPDATE durin_sessions SET revoked_at = ? WHERE (id = ? OR parent_id = ?) AND revoked_at IS NULL", t, std::string(parent_id),
           std::string(parent_id));
    h.exec("DELETE FROM durin_codes WHERE parent_id = ?", std::string(parent_id));
}

// End every sign-in the user has, on every device.
template<typename H>
auto sign_out_everywhere(H& h, std::string_view user_id, long long t = now()) -> void {
    h.exec("UPDATE durin_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", t, std::string(user_id));
    h.exec("DELETE FROM durin_codes WHERE parent_id IN (SELECT id FROM durin_sessions WHERE user_id = ?)", std::string(user_id));
}

struct HostSession {
    std::string host;
    long long created_at = 0;
};

// The app hosts this sign-in has opened, newest first.
template<typename H>
auto hosts_of(H& h, std::string_view parent_id) -> std::vector<HostSession> {
    std::vector<HostSession> out;
    for (auto& [host, created] : h.template query_as<std::string, long long>(
             "SELECT host, MAX(created_at) FROM durin_sessions WHERE parent_id = ? AND revoked_at IS NULL GROUP BY host ORDER BY 2 DESC",
             std::string(parent_id))) {
        out.push_back({std::move(host), created});
    }
    return out;
}

// ── owners, people and invites ───────────────────────────────────────────────
// Only a one-use link makes an account: an owner link (`owner` on the server's command line) makes an
// owner, an owner's invite makes anyone else; anyone signed in may add passkeys to their own account only.

template<typename H>
auto is_owner(H& h, std::string_view user_id) -> bool {
    return h.template scalar<long long>("SELECT owner FROM durin_users WHERE user_id = ?", std::string(user_id)).value_or(0) != 0;
}

struct Person {
    std::string user_id;
    std::string name;
    bool owner = false;
    long long created_at = 0;
    long long passkeys = 0;
};

// Everyone with an account, owners first.
template<typename H>
auto people(H& h) -> std::vector<Person> {
    std::vector<Person> out;
    for (auto& [id, name, owner, created, keys] : h.template query_as<std::string, std::string, long long, long long, long long>(
             "SELECT u.user_id, u.name, u.owner, u.created_at,"
             " (SELECT COUNT(*) FROM auth_passkeys k WHERE k.user_id = u.user_id)"
             " FROM durin_users u ORDER BY u.owner DESC, u.name")) {
        out.push_back({std::move(id), std::move(name), owner != 0, created, keys});
    }
    return out;
}

// Delete an account that is not an owner's, with its passkeys, sessions and invites.
template<typename H>
auto remove_person(H& h, std::string_view user_id, long long t = now()) -> bool {
    if (is_owner(h, user_id) || name_of(h, user_id).empty()) return false;
    sign_out_everywhere(h, user_id, t);
    h.exec("DELETE FROM durin_invites WHERE created_by = ?", std::string(user_id));
    h.exec("DELETE FROM durin_sessions WHERE user_id = ?", std::string(user_id));
    h.exec("DELETE FROM durin_users WHERE user_id = ?", std::string(user_id));
    return web::auth::delete_user(h, user_id);
}

enum class Link : std::uint8_t { member, owner };

template<typename H>
auto mint_link(H& h, Link kind, std::optional<std::string> by, long long lifetime, long long t) -> std::string {
    h.exec("DELETE FROM durin_invites WHERE expires_at < ?", t);
    const auto code = random_token();
    h.exec("INSERT INTO durin_invites (id, code_hash, created_by, owner, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)", random_id(),
           hash(code), by, kind == Link::owner ? 1 : 0, t, t + lifetime);
    return code;
}

// A one-use code that makes an owner. Only the server's command line calls this. A new one replaces
// the last, so there is never more than one open.
template<typename H>
auto mint_owner_link(H& h, const Settings& s = settings(), long long t = now()) -> std::string {
    h.exec("DELETE FROM durin_invites WHERE owner = 1");
    return mint_link(h, Link::owner, std::nullopt, s.owner_link_seconds, t);
}


// A one-use link code for one new account. Only its hash is stored.
template<typename H>
auto mint_invite(H& h, std::string_view by, const Settings& s = settings(), long long t = now()) -> std::string {
    return mint_link(h, Link::member, std::string(by), s.invite_seconds, t);
}

template<typename H>
auto invite_ok(H& h, std::string_view code, long long t = now()) -> bool {
    if (code.empty() || code.size() > 128) return false;
    return h.template scalar<long long>("SELECT COUNT(*) FROM durin_invites WHERE code_hash = ? AND expires_at > ?", hash(code), t)
               .value_or(0) > 0;
}

// Whether a live link makes an owner (for the page's wording).
template<typename H>
auto is_owner_link(H& h, std::string_view code, long long t = now()) -> bool {
    return h.template scalar<long long>("SELECT COUNT(*) FROM durin_invites WHERE code_hash = ? AND owner = 1 AND expires_at > ?", hash(code), t)
               .value_or(0) > 0;
}

// Spend a link: what account it makes, or nothing if it was used, cancelled or has expired.
template<typename H>
auto take_invite(H& h, std::string_view code, long long t = now()) -> std::optional<Link> {
    if (code.empty() || code.size() > 128) return std::nullopt;
    const auto rows = h.template query_as<std::string, long long>(
        "DELETE FROM durin_invites WHERE code_hash = ? AND expires_at > ? RETURNING id, owner", hash(code), t);
    if (rows.empty()) return std::nullopt;
    return std::get<1>(rows.front()) != 0 ? Link::owner : Link::member;
}

struct Invite {
    std::string id;
    std::string by;
    long long created_at = 0;
    long long expires_at = 0;
};

template<typename H>
auto open_invites(H& h, long long t = now()) -> std::vector<Invite> {
    std::vector<Invite> out;
    for (auto& [id, by, created, expires] : h.template query_as<std::string, std::string, long long, long long>(
             "SELECT i.id, COALESCE(u.name, ''), i.created_at, i.expires_at FROM durin_invites i"
             " LEFT JOIN durin_users u ON u.user_id = i.created_by WHERE i.owner = 0 AND i.expires_at > ? ORDER BY i.created_at DESC",
             t)) {
        out.push_back({std::move(id), std::move(by), created, expires});
    }
    return out;
}

template<typename H>
auto revoke_invite(H& h, std::string_view id) -> void {
    h.exec("DELETE FROM durin_invites WHERE id = ?", std::string(id));
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────

// The signed-in user at the auth host, from the request's cookie.
template<typename H>
auto auth_session(H& h, const web::Request& req) -> std::optional<Who> {
    if (request_host(req) != settings().auth_host) return std::nullopt;
    auto who = check(h, req.cookies.get(cookie_name), settings().auth_host);
    if (who && who->session_id != who->parent_id) return std::nullopt;
    return who;
}

// The signed-in user at the auth host, if they are an owner.
template<typename H>
auto owner_session(H& h, const web::Request& req) -> std::optional<Who> {
    auto who = auth_session(h, req);
    if (!who || !is_owner(h, who->user_id)) return std::nullopt;
    return who;
}

inline auto set_cookie(web::Response& resp, const std::string& token, bool remember, long long max_age) -> void {
    resp.cookies.data[std::string(cookie_name)] = token;
    if (remember) resp.keep_cookies_for(std::chrono::seconds(max_age));
}

inline auto auth_url(std::string_view path_and_query = "/") -> std::string {
    return "https://" + settings().auth_host + std::string(path_and_query);
}

// Where a visitor with no session goes first: the app host's own /.durin/start, which plants a nonce
// cookie and then sends the browser on to sign in. `path` is the path and query they asked for.
inline auto start_url(std::string_view host, std::string_view path) -> std::string {
    return "https://" + std::string(host) + "/.durin/start?rd=" + sanitize::url_encode(std::string(path));
}

// Forward auth. A live session cookie for the original host: 200 with the user header. Otherwise the
// start address (carrying the original path, so sign-in can come back to it), as a 302 or, for
// proxies that only take 2xx/401/403 (nginx auth_request), as a 401 carrying Location.
template<typename H>
auto verify(H& h, const web::Request& req, bool redirect) -> web::Response {
    const auto o = redirect ? original_forwarded(req) : original_url(req);
    if (!is_app_host(o.host)) {
        return web::Response{.body = "not a gated host", .content_type = "text/plain", .status = web::status::forbidden};
    }
    if (const auto who = check(h, req.cookies.get(cookie_name), o.host)) {
        web::Response ok{.body = "", .content_type = "text/plain"};
        ok.headers.data[settings().user_header] = who->name;
        return ok;
    }
    const auto path = is_local_path(o.path) ? o.path : std::string("/");
    const auto to = start_url(o.host, path);
    if (redirect) return web::redirect(to, web::status::found);
    web::Response no{.body = "sign in", .content_type = "text/plain", .status = web::status::unauthorized};
    no.headers.data["Location"] = to;
    return no;
}

} // namespace durin
