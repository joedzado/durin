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
#include <revet/rate_limit.hpp>
#include <revet/sanitize.hpp>
#include <revet/web.hpp>
#include <revet/webauthn.hpp>

namespace durin {

struct Settings {
    std::string auth_host;                // DURIN_AUTH_HOST (required): where sign-in happens, the passkey RP ID
    std::string suffix;                   // DURIN_SUFFIX: app hosts are <name>.<suffix>; default: the auth host
                                          // without its first label
    bool original_url = false;            // DURIN_PROXY: "forwarded" (default; X-Forwarded-Host/-Uri: Caddy,
                                          // Traefik) or "original" (X-Original-URL: nginx)
    std::string user_header = "Remote-User"; // DURIN_USER_HEADER: the header verify answers with the account name
    std::string setup_code;               // DURIN_SETUP_CODE: creates an owner while there is none; ignored otherwise
    long long idle_seconds = 5 * 60;      // DURIN_IDLE_SECONDS: unremembered sign-in ends after this much quiet
    long long max_seconds = 12 * 3600;    // DURIN_MAX_SECONDS: ... and after this long in any case
    long long remember_seconds = 30 * 86400; // DURIN_REMEMBER_SECONDS: "remember me" lasts this long
    long long code_seconds = 60;          // one-time code lifetime
    long long invite_seconds = 7 * 86400; // an invite link lasts this long, for one account
    long long touch_seconds = 15;         // write last_seen at most this often
};

inline constexpr std::string_view cookie_name = "__Host-durin";

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
        std::string proxy;
        text("DURIN_PROXY", proxy);
        c.original_url = proxy == "original";
        for (auto* v : {&c.auth_host, &c.suffix}) {
            std::ranges::transform(*v, v->begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        }
        if (c.suffix.empty()) {
            if (const auto dot = c.auth_host.find('.'); dot != std::string::npos) c.suffix = c.auth_host.substr(dot + 1);
        }
        text("DURIN_SETUP_CODE", c.setup_code);
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

// Forwarding headers count only from a proxy in REVET_TRUSTED_PROXIES; anyone else gets their Host.
inline auto from_trusted_proxy(const web::Request& req) -> bool {
    return !req.peer_ip.empty() && web::rate_limit::trusted_proxies().contains(req.peer_ip);
}

struct Original {
    std::string host; // without a port
    std::string path; // path and query as sent; callers check it with is_local_path
};

// The request the browser made, which a forward-auth request is asking about. Only the headers of the
// configured proxy style are read, so a client cannot slip in the other style's header:
//   forwarded: X-Forwarded-Host + X-Forwarded-Uri (Caddy and Traefik set both on forward auth, and
//              X-Forwarded-Host on proxied requests)
//   original:  X-Original-URL: <scheme>://<host><path> (nginx, as the recipe sets it on every location)
// Without them (or from an untrusted peer): the Host header and the request's own path.
inline auto original(const web::Request& req, const Settings& s = settings()) -> Original {
    Original o{strip_port(req.headers.get("host")), ""};
    if (!from_trusted_proxy(req)) return o;
    if (s.original_url) {
        const std::string url = req.headers.get("x-original-url");
        const auto sep = url.find("://");
        if (sep == std::string::npos) return o;
        const auto rest = std::string_view(url).substr(sep + 3);
        const auto slash = rest.find('/');
        const auto authority = rest.substr(0, slash);
        if (authority.empty() || authority.contains('@')) return o;
        return {strip_port(std::string(authority)), slash == std::string_view::npos ? "/" : std::string(rest.substr(slash))};
    }
    if (auto h = req.headers.get("x-forwarded-host"); !h.empty()) o.host = strip_port(h);
    o.path = req.headers.get("x-forwarded-uri");
    return o;
}

// The host the browser asked for, without a port.
inline auto request_host(const web::Request& req) -> std::string {
    return original(req).host;
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

inline auto setup_code_ok(std::string_view given, const Settings& s = settings()) -> bool {
    return !s.setup_code.empty() && !given.empty() && web::crypto::secure_eq(given, s.setup_code);
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
    h.exec("CREATE TABLE IF NOT EXISTS durin_invites ("
           " id TEXT PRIMARY KEY,"
           " code_hash TEXT NOT NULL UNIQUE,"
           " created_by TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,"
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
           " expires_at BIGINT NOT NULL)");
}

// ── users ────────────────────────────────────────────────────────────────────

template<typename H>
auto user_count(H& h) -> long long {
    return h.template scalar<long long>("SELECT COUNT(*) FROM durin_users").value_or(0);
}

// The owner makes accounts by invite. While there is no owner, the setup code makes one.
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

// A one-time code that lets `host` open a session under the sign-in `parent_id`.
template<typename H>
auto mint_code(H& h, std::string_view parent_id, std::string_view host, const Settings& s = settings(), long long t = now()) -> std::string {
    const auto code = random_token();
    h.exec("INSERT INTO durin_codes (code_hash, parent_id, host, expires_at) VALUES (?, ?, ?, ?)", hash(code), std::string(parent_id),
           std::string(host), t + s.code_seconds);
    return code;
}

struct Redeemed {
    Started started;
    bool remember = false;
    long long expires_at = 0;
};

// Spend a code at `host`. Single use: it is gone whether or not it was for this host.
template<typename H>
auto redeem_code(H& h, std::string_view code, std::string_view host, const Settings& s = settings(), long long t = now())
    -> std::optional<Redeemed> {
    if (code.empty() || code.size() > 128) return std::nullopt;
    web::auth::detail::Tx<H> tx(h);
    const auto rows = h.template query_as<std::string, std::string>(
        "DELETE FROM durin_codes WHERE code_hash = ? AND expires_at > ? RETURNING parent_id, host", hash(code), t);
    if (rows.empty()) {
        tx.commit();
        return std::nullopt;
    }
    const auto& [parent, code_host] = rows.front();
    const auto p = h.template query_as<std::string, long long, long long, long long, std::optional<long long>>(
        "SELECT user_id, remember, last_seen_at, expires_at, revoked_at FROM durin_sessions WHERE id = ? AND parent_id IS NULL", parent);
    if (code_host != host || p.empty()) {
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
// The first account (made with the setup code) is the owner. After that, only an owner's invite link
// makes an account; anyone signed in may add passkeys to their own account only.

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

// A one-use link code for one new account. Only its hash is stored.
template<typename H>
auto mint_invite(H& h, std::string_view by, const Settings& s = settings(), long long t = now()) -> std::string {
    h.exec("DELETE FROM durin_invites WHERE expires_at < ?", t);
    const auto code = random_token();
    h.exec("INSERT INTO durin_invites (id, code_hash, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?)", random_id(), hash(code),
           std::string(by), t, t + s.invite_seconds);
    return code;
}

template<typename H>
auto invite_ok(H& h, std::string_view code, long long t = now()) -> bool {
    if (code.empty() || code.size() > 128) return false;
    return h.template scalar<long long>("SELECT COUNT(*) FROM durin_invites WHERE code_hash = ? AND expires_at > ?", hash(code), t)
               .value_or(0) > 0;
}

// Spend an invite. False if it was already used, revoked or expired.
template<typename H>
auto take_invite(H& h, std::string_view code, long long t = now()) -> bool {
    if (code.empty() || code.size() > 128) return false;
    return !h.template query_as<std::string>("DELETE FROM durin_invites WHERE code_hash = ? AND expires_at > ? RETURNING id", hash(code), t)
                .empty();
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
             " LEFT JOIN durin_users u ON u.user_id = i.created_by WHERE i.expires_at > ? ORDER BY i.created_at DESC",
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

// Forward auth. A live session cookie for the original host: 200 with the user header. Otherwise the
// sign-in address (with the original address, so sign-in can come back to it), as a 302 or, for
// proxies that only take 2xx/401/403 (nginx auth_request), as a 401 carrying Location.
template<typename H>
auto verify(H& h, const web::Request& req, bool redirect) -> web::Response {
    const auto o = original(req);
    if (!is_app_host(o.host)) {
        return web::Response{.body = "not a gated host", .content_type = "text/plain", .status = web::status::forbidden};
    }
    if (const auto who = check(h, req.cookies.get(cookie_name), o.host)) {
        web::Response ok{.body = "", .content_type = "text/plain"};
        ok.headers.data[settings().user_header] = who->name;
        return ok;
    }
    const auto path = is_local_path(o.path) ? o.path : std::string("/");
    const auto to = auth_url("/?rd=" + sanitize::url_encode("https://" + o.host + path));
    if (redirect) return web::redirect(to, web::status::found);
    web::Response no{.body = "sign in", .content_type = "text/plain", .status = web::status::unauthorized};
    no.headers.data["Location"] = to;
    return no;
}

} // namespace durin
