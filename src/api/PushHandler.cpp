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

namespace bsfchat {

using json = nlohmann::json;

namespace {

void send_error(httplib::Response& res, int status, const MatrixError& err) {
    res.status = status;
    res.set_content(err.to_json().dump(), "application/json");
}

// Validates a client-supplied push gateway URL.
//
// This is the SSRF gate. /pushers/set is the one endpoint where an ordinary user
// gets to name a URL that the server itself will later request, so anything
// accepted here is a request the server can be made to issue on the user's
// behalf. Absolute http(s) only, and — when the deployment has configured them —
// restricted to an explicit prefix allowlist.
bool gateway_url_allowed(const std::string& url, const PushConfig& cfg, std::string& why) {
    const bool http = url.rfind("http://", 0) == 0;
    const bool https = url.rfind("https://", 0) == 0;
    if (!http && !https) {
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
    if (cfg.allowed_gateway_prefixes.empty()) return true;

    for (const auto& prefix : cfg.allowed_gateway_prefixes) {
        if (!prefix.empty() && url.rfind(prefix, 0) == 0) return true;
    }
    why = "data.url is not an allowed push gateway for this server";
    return false;
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
        get_logger()->warn("Push: rejected pusher registration from {} for URL {} ({})",
                           *user_id, url, why);
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

    // `append` defaults to false, which per the spec means "this pushkey now
    // belongs to me alone". That is a security property, not a tidiness one: a
    // device token recycled onto a different account must stop delivering the
    // previous account's messages.
    if (!body.value("append", false)) {
        int removed = store_.delete_pushers_by_pushkey_except(pushkey, *user_id, app_id);
        if (removed > 0) {
            get_logger()->info("Push: pushkey reassigned; removed {} stale pusher(s)", removed);
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
