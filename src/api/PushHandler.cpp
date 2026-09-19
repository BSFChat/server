#include "api/PushHandler.h"

#include "core/Config.h"
#include "core/Logger.h"
#include "http/Middleware.h"
#include "http/Router.h"
#include "push/PushService.h"
#include "store/SqliteStore.h"

#include <bsfchat/ErrorCodes.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace bsfchat {

using json = nlohmann::json;

namespace {

void send_error(httplib::Response& res, int status, const MatrixError& err) {
    res.status = status;
    res.set_content(err.to_json().dump(), "application/json");
}

// ── Gateway URL validation ─────────────────────────────────────────────────
//
// /pushers/set is the one endpoint where an ordinary user names a URL that the
// SERVER will later POST to, carrying notification data. Two independent
// things follow from that, and both are enforced below:
//
//   * it is a server-side request forgery surface — whatever is accepted here
//     is a request the server can be made to issue from inside its own
//     network;
//   * it is an EGRESS surface — whatever is accepted here is somewhere message
//     data goes. A default-open allowlist turned a notification feature into a
//     self-serve exfiltration feed for anyone with an account.
//
// So: the operator's allowlist is mandatory (empty means nothing is permitted,
// and Config::validate forces push off in that case), it is matched on
// scheme + host + port + path boundary rather than as a raw string prefix, and
// internal addresses are refused on top of that unless the operator opts in.

// The longest a gateway URL may be. Generous for a real notify endpoint, small
// enough that the field is not storage, not a log-flood lever, and not a
// parser stress test.
constexpr std::size_t kMaxGatewayUrlLen = 2048;

// An IPv4 address in any form inet_aton() accepts, which is what the resolver
// behind httplib::Client will accept: 1 to 4 parts, each decimal, octal
// (leading 0) or hex (leading 0x).
//
// Parsing only dotted-quad decimal is the classic SSRF-filter hole. "0177.0.0.1",
// "0x7f.0.0.1" and "127.1" all reach 127.0.0.1 and all read as ordinary public
// hosts to a naive parser.
bool parse_ipv4(const std::string& host, uint32_t& addr) {
    std::vector<uint64_t> parts;
    std::size_t i = 0;
    while (i <= host.size()) {
        std::size_t dot = host.find('.', i);
        const std::string tok = host.substr(i, dot == std::string::npos ? std::string::npos
                                                                        : dot - i);
        if (tok.empty()) return false;

        int base = 10;
        std::size_t pos = 0;
        if (tok.size() > 2 && tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X')) {
            base = 16;
            pos = 2;
        } else if (tok.size() > 1 && tok[0] == '0') {
            base = 8;
            pos = 1;
        }
        uint64_t value = 0;
        for (; pos < tok.size(); ++pos) {
            const auto c = static_cast<unsigned char>(tok[pos]);
            int digit;
            if (c >= '0' && c <= '9') digit = c - '0';
            else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
            else return false;
            if (digit >= base) return false;
            value = value * base + static_cast<uint64_t>(digit);
            if (value > 0xffffffffULL) return false;
        }
        parts.push_back(value);
        if (parts.size() > 4) return false;
        if (dot == std::string::npos) break;
        i = dot + 1;
    }
    if (parts.empty()) return false;

    // inet_aton's short forms: the last part fills the remaining low bytes.
    const std::size_t n = parts.size();
    for (std::size_t k = 0; k + 1 < n; ++k) {
        if (parts[k] > 0xff) return false;
    }
    const uint64_t last_max = (n == 1) ? 0xffffffffULL
                            : (n == 2) ? 0xffffffULL
                            : (n == 3) ? 0xffffULL
                                       : 0xffULL;
    if (parts[n - 1] > last_max) return false;

    uint64_t result = parts[n - 1];
    for (std::size_t k = 0; k + 1 < n; ++k) {
        result |= parts[k] << (8 * (3 - k));
    }
    addr = static_cast<uint32_t>(result);
    return true;
}

std::string ipv4_to_string(uint32_t addr) {
    return std::to_string((addr >> 24) & 0xff) + "." + std::to_string((addr >> 16) & 0xff) +
           "." + std::to_string((addr >> 8) & 0xff) + "." + std::to_string(addr & 0xff);
}

// Expands an IPv6 literal (brackets already stripped) into its eight groups.
// False for anything that does not parse — the caller treats that as internal,
// because a literal this cannot read is not a literal it can clear.
bool parse_ipv6(const std::string& host, uint16_t groups[8]) {
    const auto dbl = host.find("::");
    if (dbl != std::string::npos && host.find("::", dbl + 1) != std::string::npos) return false;

    auto split_groups = [](const std::string& s, std::vector<uint16_t>& out) {
        if (s.empty()) return true;
        std::size_t i = 0;
        while (true) {
            const auto colon = s.find(':', i);
            const std::string tok =
                s.substr(i, colon == std::string::npos ? std::string::npos : colon - i);
            if (tok.empty() || tok.size() > 4) return false;
            uint32_t value = 0;
            for (char ch : tok) {
                const auto c = static_cast<unsigned char>(ch);
                int digit;
                if (c >= '0' && c <= '9') digit = c - '0';
                else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
                else return false;
                value = value * 16 + static_cast<uint32_t>(digit);
            }
            out.push_back(static_cast<uint16_t>(value));
            if (colon == std::string::npos) break;
            i = colon + 1;
        }
        return true;
    };

    std::vector<uint16_t> head;
    std::vector<uint16_t> tail;
    if (dbl == std::string::npos) {
        if (!split_groups(host, head)) return false;
        if (head.size() != 8) return false;
    } else {
        if (!split_groups(host.substr(0, dbl), head)) return false;
        if (!split_groups(host.substr(dbl + 2), tail)) return false;
        if (head.size() + tail.size() > 7) return false;
    }
    std::size_t g = 0;
    for (auto v : head) groups[g++] = v;
    while (g < 8 - tail.size()) groups[g++] = 0;
    for (auto v : tail) groups[g++] = v;
    return true;
}

bool ends_with(const std::string& s, const char* suffix) {
    const std::string suf(suffix);
    return s.size() >= suf.size()
        && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

bool ipv4_is_internal(uint32_t addr) {
    const unsigned a = (addr >> 24) & 0xff;
    const unsigned b = (addr >> 16) & 0xff;
    const unsigned c = (addr >> 8) & 0xff;
    if (a == 127) return true;                              // loopback
    if (a == 0) return true;                                // "this host"
    if (a == 10) return true;                               // RFC1918
    if (a == 172 && b >= 16 && b <= 31) return true;
    if (a == 192 && b == 168) return true;
    if (a == 169 && b == 254) return true;                  // link-local / metadata
    if (a == 100 && b >= 64 && b <= 127) return true;       // CGNAT
    if (a == 192 && b == 0 && c == 0) return true;
    if (a >= 224) return true;                              // multicast + broadcast
    return false;
}

// Targets that only make sense as an attack when a USER picks them.
//
// `host` must already be normalised (lowercased, trailing dot stripped, IPv6
// brackets removed, numeric IPv4 canonicalised). Unparseable IPv6 is reported
// as internal: failing closed on a literal this cannot read is the only safe
// answer, and no real gateway is addressed that way.
bool host_is_internal(const std::string& host) {
    if (host.empty()) return true;

    if (host == "localhost" || ends_with(host, ".localhost")
        || ends_with(host, ".local") || ends_with(host, ".internal")
        || ends_with(host, ".home.arpa"))
        return true;

    uint32_t v4 = 0;
    if (parse_ipv4(host, v4)) return ipv4_is_internal(v4);

    if (host.find(':') != std::string::npos) {
        uint16_t g[8];
        if (!parse_ipv6(host, g)) return true;

        bool all_zero = true;
        for (auto v : g) {
            if (v != 0) all_zero = false;
        }
        if (all_zero) return true;                                   // ::
        bool loopback = g[7] == 1;
        for (int i = 0; i < 7 && loopback; ++i) loopback = g[i] == 0;
        if (loopback) return true;                                   // ::1
        if ((g[0] & 0xffc0) == 0xfe80) return true;                  // fe80::/10
        if ((g[0] & 0xfe00) == 0xfc00) return true;                  // fc00::/7
        // ::ffff:a.b.c.d (mapped) and ::a.b.c.d (compat), in every spelling.
        bool zero_prefix = true;
        for (int i = 0; i < 5; ++i) {
            if (g[i] != 0) zero_prefix = false;
        }
        if (zero_prefix && (g[5] == 0xffff || g[5] == 0)) {
            const uint32_t embedded = (static_cast<uint32_t>(g[6]) << 16) | g[7];
            return ipv4_is_internal(embedded);
        }
        return false;
    }

    // A bare name with no dot resolves through the deployment's own search
    // domain — "db", "identity", a compose service name. Never a public
    // push gateway.
    return host.find('.') == std::string::npos;
}

// An absolute http(s) URL, split into the pieces the allowlist compares.
struct GatewayUrl {
    std::string scheme;   // "http" | "https"
    std::string host;     // normalised: lowercase, no trailing dot, no brackets,
                          // numeric IPv4 canonicalised to dotted quad
    std::string port;     // always explicit; the scheme default when absent
    std::string path;     // always begins with '/'; query and fragment dropped
};

bool parse_gateway_url(const std::string& url, GatewayUrl& out) {
    const bool https = url.rfind("https://", 0) == 0;
    const bool http = url.rfind("http://", 0) == 0;
    if (!http && !https) return false;
    out.scheme = https ? "https" : "http";

    const std::size_t start = out.scheme.size() + 3;
    std::size_t end = url.find_first_of("/?#", start);
    if (end == std::string::npos) end = url.size();
    std::string authority = url.substr(start, end - start);
    if (authority.empty()) return false;

    out.port = https ? "443" : "80";
    if (authority.front() == '[') {                         // [::1]:8448
        const auto close = authority.find(']');
        if (close == std::string::npos) return false;
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':') return false;
            out.port = authority.substr(close + 2);
        }
        authority = authority.substr(1, close - 1);
    } else if (const auto colon = authority.rfind(':');
               colon != std::string::npos && authority.find(':') == colon) {
        out.port = authority.substr(colon + 1);
        authority.resize(colon);
    }
    if (authority.empty() || out.port.empty()) return false;
    if (out.port.find_first_not_of("0123456789") != std::string::npos) return false;

    std::transform(authority.begin(), authority.end(), authority.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    // "example.com." and "example.com" are the same name to the resolver, and
    // "127.0.0.1." is the same address. Normalise so neither the allowlist nor
    // the internal-address check can be stepped around with a trailing dot.
    while (!authority.empty() && authority.back() == '.') authority.pop_back();
    if (authority.empty()) return false;

    // Canonicalise numeric IPv4 so an alternate encoding cannot masquerade as a
    // different host than the one the allowlist names, or as a public one.
    uint32_t v4 = 0;
    if (parse_ipv4(authority, v4)) authority = ipv4_to_string(v4);
    out.host = std::move(authority);

    if (end >= url.size() || url[end] != '/') {
        out.path = "/";
    } else {
        const auto stop = url.find_first_of("?#", end);
        out.path = url.substr(end, stop == std::string::npos ? std::string::npos : stop - end);
    }
    if (out.path.empty()) out.path = "/";
    return true;
}

// Whether `url_path` is at or below `prefix_path`, on a path-segment boundary.
// "/_matrix/push/v1/" must authorise "/_matrix/push/v1/notify" but not
// "/_matrix/push/v1backdoor".
bool path_is_within(const std::string& prefix_path, const std::string& url_path) {
    std::string base = prefix_path;
    while (base.size() > 1 && base.back() == '/') base.pop_back();
    if (base == "/" || base.empty()) return true;
    if (url_path == base) return true;
    return url_path.size() > base.size() && url_path.compare(0, base.size(), base) == 0
        && url_path[base.size()] == '/';
}

// Validates a client-supplied push gateway URL. See the block comment above.
bool gateway_url_allowed(const std::string& url, const PushConfig& cfg, std::string& why) {
    if (url.size() > kMaxGatewayUrlLen) {
        why = "data.url is too long";
        return false;
    }
    if (url.rfind("http://", 0) != 0 && url.rfind("https://", 0) != 0) {
        why = "data.url must be an absolute http:// or https:// URL";
        return false;
    }
    // Reject credentials-in-URL and anything with control characters, both of
    // which are request-smuggling shapes rather than legitimate gateway URLs.
    if (url.find('@') != std::string::npos) {
        why = "data.url must not contain userinfo";
        return false;
    }
    if (std::any_of(url.begin(), url.end(),
                    [](unsigned char c) { return c < 0x21 || c == 0x7f; })) {
        why = "data.url contains invalid characters";
        return false;
    }

    GatewayUrl target;
    if (!parse_gateway_url(url, target)) {
        why = "data.url is not a well-formed absolute http(s) URL";
        return false;
    }

    // Default CLOSED. An empty allowlist is not "any gateway" — it is "no
    // gateway", because the alternative makes every account its own egress
    // channel for message content. Config::validate turns push off entirely in
    // this state, so reaching here at all means the config was changed under a
    // running process.
    if (cfg.allowed_gateway_prefixes.empty()) {
        why = "this server has no push.allowed_gateway_prefixes configured, so no push "
              "gateway may be registered";
        return false;
    }

    bool allowed = false;
    for (const auto& prefix : cfg.allowed_gateway_prefixes) {
        GatewayUrl entry;
        if (prefix.empty() || !parse_gateway_url(prefix, entry)) continue;
        // Scheme, host and port must match exactly. A raw string prefix would
        // let "https://push.example.com" also authorise
        // "https://push.example.com.evil.tld/", which is the attacker's own
        // collector wearing the allowlisted name as a prefix.
        if (entry.scheme != target.scheme || entry.host != target.host
            || entry.port != target.port)
            continue;
        if (!path_is_within(entry.path, target.path)) continue;
        allowed = true;
        break;
    }
    if (!allowed) {
        why = "data.url is not an allowed push gateway for this server";
        return false;
    }

    // Applied on top of the allowlist, not instead of it. The allowlist answers
    // "which gateway"; this answers "may this server be made to talk to the
    // inside of its own network at all", so an entry typo'd onto an internal
    // host fails closed. Sygnal in the same compose file is a real shape, so it
    // is an explicit opt-in rather than an impossibility.
    //
    // Note what this cannot cover: a public name that RESOLVES to an internal
    // address. Closing that needs a post-resolution check in the HTTP client.
    // With a mandatory allowlist the remaining exposure is limited to hosts the
    // operator named, which is a deliberate trade rather than an oversight.
    if (!cfg.allow_internal_gateway && host_is_internal(target.host)) {
        why = "data.url points at an internal address; set push.allow_internal_gateway "
              "if this deployment's gateway really is on the internal network";
        return false;
    }
    return true;
}

json pusher_to_json(const SqliteStore::Pusher& p) {
    auto data = json::parse(p.data_json, nullptr, false);
    if (data.is_discarded() || !data.is_object()) data = json::object();
    // `url` and `format` are stored as columns because delivery and privacy
    // depend on them; echo them back inside `data` where the spec puts them.
    data["url"] = p.url;
    if (!p.format.empty()) data["format"] = p.format;
    return json{
        {"pushkey", p.pushkey},
        {"kind", p.kind},
        {"app_id", p.app_id},
        {"app_display_name", p.app_display_name},
        {"device_display_name", p.device_display_name},
        {"profile_tag", p.profile_tag},
        {"lang", p.lang},
        {"data", std::move(data)},
    };
}

} // namespace

PushHandler::PushHandler(SqliteStore& store, PushService& push, const Config& config)
    : store_(store), push_(push), config_(config) {}

void PushHandler::handle_set_pusher(const httplib::Request& req, httplib::Response& res) {
    auto auth_header = req.get_header_value("Authorization");
    auto user_id = authenticate(store_, auth_header);
    if (!user_id) {
        return send_error(res, 401, auth_error(auth_header));
    }

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        return send_error(res, 400, MatrixError::bad_json());
    }
    if (!body.is_object()) {
        return send_error(res, 400, MatrixError::bad_json("Request body must be an object"));
    }

    const std::string pushkey = body.value("pushkey", "");
    const std::string app_id = body.value("app_id", "");
    if (pushkey.empty() || app_id.empty()) {
        return send_error(res, 400,
            MatrixError::invalid_param("pushkey and app_id are required"));
    }
    // Bounded so the tables can't be used as arbitrary storage.
    if (pushkey.size() > 512 || app_id.size() > 128) {
        return send_error(res, 400, MatrixError::invalid_param("pushkey or app_id too long"));
    }

    // `kind: null` deletes the pusher, per the spec.
    auto kind_it = body.find("kind");
    if (kind_it != body.end() && kind_it->is_null()) {
        store_.delete_pusher(*user_id, app_id, pushkey);
        res.set_content("{}", "application/json");
        return;
    }

    const std::string kind = body.value("kind", "");
    if (kind != "http") {
        // Only the HTTP gateway kind is implemented. Saying so beats silently
        // storing an "email" pusher that will never deliver anything.
        return send_error(res, 400,
            MatrixError::invalid_param("Only kind \"http\" is supported by this server"));
    }

    json data = json::object();
    if (auto it = body.find("data"); it != body.end() && it->is_object()) data = *it;
    const std::string url = data.value("url", "");
    if (url.empty()) {
        return send_error(res, 400,
            MatrixError::invalid_param("data.url is required for kind \"http\""));
    }
    std::string why;
    if (!gateway_url_allowed(url, config_.push, why)) {
        // log_safe, not the raw URL: the check immediately above rejected this
        // string for containing control characters, and writing it to the log
        // unescaped would let any account forge whole log records — including
        // the auth lockout and login lines that ARE this server's
        // security-event record.
        get_logger()->warn("Push: rejected pusher registration from {} for URL {} ({})",
                           log_safe(*user_id), log_safe(url), why);
        return send_error(res, 400, MatrixError::invalid_param(why));
    }
    const std::string format = data.value("format", "");
    if (!format.empty() && format != "event_id_only") {
        return send_error(res, 400,
            MatrixError::invalid_param("data.format must be omitted or \"event_id_only\""));
    }

    SqliteStore::Pusher pusher;
    pusher.user_id = *user_id;
    pusher.app_id = app_id;
    pusher.pushkey = pushkey;
    pusher.kind = kind;
    pusher.app_display_name = body.value("app_display_name", "");
    pusher.device_display_name = body.value("device_display_name", "");
    pusher.profile_tag = body.value("profile_tag", "");
    pusher.lang = body.value("lang", "");
    pusher.url = url;
    pusher.format = format;
    // url/format are promoted to columns; keep the rest of `data` verbatim so a
    // gateway that needs extra fields still receives them.
    {
        json rest = data;
        rest.erase("url");
        rest.erase("format");
        pusher.data_json = rest.dump();
    }
    if (auto token = extract_access_token(auth_header)) {
        if (auto session = store_.get_session_by_token(*token)) {
            pusher.device_id = session->device_id;
        }
    }

    store_.upsert_pusher(pusher);

    // `append` defaults to false, which per the spec means "this App ID +
    // pushkey pair now belongs to me alone". That is a security property, not a
    // tidiness one: a device token recycled onto a different account must stop
    // delivering the previous account's messages.
    //
    // Scoped to the SAME app_id, which is both what the spec says and the only
    // defensible reading: a pushkey is an APNs/FCM token issued to one
    // application, so it says nothing at all about a row with a different
    // app_id. Unscoped, knowing a pushkey was an authorisation to delete
    // unrelated rows belonging to other people.
    //
    // What remains, and is a known trade rather than an oversight: an attacker
    // who learns a victim's device token can still claim it and stop the
    // victim's notifications. Not fixable without breaking the recycled-token
    // case, which is the worse leak (the previous owner's messages would keep
    // arriving on someone else's phone). Logged so it is at least visible.
    if (!body.value("append", false)) {
        int removed = store_.delete_pushers_by_pushkey_except(pushkey, app_id, *user_id);
        if (removed > 0) {
            get_logger()->info(
                "Push: app_id {} pushkey reassigned to {}; removed {} pusher(s) held by "
                "other accounts", log_safe(app_id), log_safe(*user_id), removed);
        }
    }

    res.set_content("{}", "application/json");
}

void PushHandler::handle_get_pushers(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        return send_error(res, 401, auth_error(req.get_header_value("Authorization")));
    }

    auto pushers = json::array();
    for (const auto& p : store_.get_pushers(*user_id)) {
        pushers.push_back(pusher_to_json(p));
    }
    res.set_content(json{{"pushers", std::move(pushers)}}.dump(), "application/json");
}

void PushHandler::handle_get_notify_level(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        return send_error(res, 401, auth_error(req.get_header_value("Authorization")));
    }
    auto match = match_route(
        "/_matrix/client/v3/bsfchat/rooms/{roomId}/notify_level", req.path);
    if (!match.matched) {
        return send_error(res, 404, MatrixError::not_found());
    }
    auto& room_id = match.params["roomId"];
    if (!store_.is_room_member(room_id, *user_id)) {
        return send_error(res, 403, MatrixError::forbidden("Not a member of this room"));
    }

    auto level = store_.get_room_notify_level(*user_id, room_id);
    const bool is_dm = store_.is_direct_room(room_id);
    res.set_content(json{
        {"level", level.value_or(is_dm ? PushService::kLevelAll : PushService::kLevelMentions)},
        // Tells the client whether it is looking at an explicit choice or the
        // server's default, so a settings UI can render "Default (mentions)".
        {"is_default", !level.has_value()},
    }.dump(), "application/json");
}

void PushHandler::handle_put_notify_level(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        return send_error(res, 401, auth_error(req.get_header_value("Authorization")));
    }
    auto match = match_route(
        "/_matrix/client/v3/bsfchat/rooms/{roomId}/notify_level", req.path);
    if (!match.matched) {
        return send_error(res, 404, MatrixError::not_found());
    }
    auto& room_id = match.params["roomId"];
    // Membership is the gate: a notification preference is per-(user, room), and
    // there is no reason to let anyone record one for a room they are not in.
    if (!store_.is_room_member(room_id, *user_id)) {
        return send_error(res, 403, MatrixError::forbidden("Not a member of this room"));
    }

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        return send_error(res, 400, MatrixError::bad_json());
    }
    const std::string level = body.value("level", "");
    if (!PushService::is_valid_level(level)) {
        return send_error(res, 400, MatrixError::invalid_param(
            "level must be one of \"all\", \"mentions\", \"none\""));
    }

    store_.set_room_notify_level(*user_id, room_id, level);
    res.set_content("{}", "application/json");
}

} // namespace bsfchat
