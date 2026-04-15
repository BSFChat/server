#include "api/EventHandler.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "http/Middleware.h"
#include "http/Router.h"
#include "store/SqliteStore.h"
#include "sync/SyncEngine.h"

#include <bsfchat/Constants.h>
#include <bsfchat/ErrorCodes.h>
#include <bsfchat/Identifiers.h>
#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <nlohmann/json.hpp>
#include <chrono>
#include <regex>

namespace bsfchat {

using json = nlohmann::json;

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// Very permissive URL detector used for the EMBED_LINKS gate. Matches any
// http(s) URL token; we intentionally don't try to parse Markdown or HTML
// — a single URL anywhere in the body triggers the check.
bool body_contains_url(const std::string& body) {
    static const std::regex re(R"(https?://[^\s<>"']+)", std::regex::icase);
    return std::regex_search(body, re);
}

bool body_mentions_everyone(const std::string& body) {
    return body.find("@everyone") != std::string::npos || body.find("@here") != std::string::npos;
}

void send_error(httplib::Response& res, int status, const MatrixError& err) {
    res.status = status;
    res.set_content(err.to_json().dump(), "application/json");
}

} // namespace

EventHandler::EventHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config)
    : store_(store), sync_engine_(sync_engine), config_(config) {}

void EventHandler::handle_send_event(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        return send_error(res, 401, MatrixError::missing_token());
    }

    // Match: PUT /rooms/{roomId}/send/{eventType}/{txnId}
    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}", req.path);
    if (!match.matched) {
        return send_error(res, 404, MatrixError::not_found());
    }

    auto& room_id = match.params["roomId"];
    auto& evt_type = match.params["eventType"];

    if (!store_.is_room_member(room_id, *user_id)) {
        return send_error(res, 403, MatrixError::forbidden("Not a member of this room"));
    }

    PermissionsEngine perms(store_, config_);
    auto user_perms = perms.compute(*user_id, room_id);

    // VIEW_CHANNEL is a prerequisite for anything happening in the room.
    if (!permission::has(user_perms, permission::kViewChannel)) {
        return send_error(res, 403, MatrixError::forbidden("No access to this channel"));
    }

    json content;
    try {
        content = json::parse(req.body);
    } catch (...) {
        return send_error(res, 400, MatrixError::bad_json());
    }

    // Additional per-event-type gates. We focus on m.room.message because
    // non-message timeline events (call signaling, etc.) use separate
    // permission semantics not worth spelling out here.
    if (evt_type == std::string(event_type::kRoomMessage)) {
        if (!permission::has(user_perms, permission::kSendMessages)) {
            return send_error(res, 403, MatrixError::forbidden("You don't have permission to send messages here"));
        }

        const std::string msgtype = content.value("msgtype", "m.text");
        const std::string body = content.value("body", "");
        const bool has_attachment = msgtype != std::string(msg_type::kText) && msgtype != std::string(msg_type::kEmote) && msgtype != std::string(msg_type::kNotice);

        if (has_attachment && !permission::has(user_perms, permission::kAttachFiles)) {
            return send_error(res, 403, MatrixError::forbidden("You don't have permission to attach files here"));
        }
        if (!body.empty() && body_contains_url(body) &&
            !permission::has(user_perms, permission::kEmbedLinks)) {
            return send_error(res, 403, MatrixError::forbidden("You don't have permission to post links here"));
        }
        if (!body.empty() && body_mentions_everyone(body) &&
            !permission::has(user_perms, permission::kMentionEveryone)) {
            return send_error(res, 403, MatrixError::forbidden("You don't have permission to mention everyone"));
        }

        // Slowmode: users with MANAGE_MESSAGES bypass it (matches Discord).
        if (!permission::has(user_perms, permission::kManageMessages)) {
            int slow = store_.get_channel_slowmode(room_id);
            if (slow > 0) {
                int64_t last = store_.get_last_message_ts(*user_id, room_id);
                int64_t now = now_ms();
                int64_t window_ms = static_cast<int64_t>(slow) * 1000;
                if (last > 0 && (now - last) < window_ms) {
                    int retry = static_cast<int>(window_ms - (now - last));
                    return send_error(res, 429,
                        MatrixError::limit_exceeded("Slowmode is enabled in this channel", retry));
                }
            }
        }
    }

    auto event_id = generate_event_id(config_.server_name);
    store_.insert_event(event_id, room_id, *user_id, evt_type, std::nullopt, content.dump(), now_ms());
    sync_engine_.notify_new_event();

    res.set_content(json{{"event_id", event_id}}.dump(), "application/json");
}

void EventHandler::handle_room_messages(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        return send_error(res, 401, MatrixError::missing_token());
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/messages", req.path);
    if (!match.matched) {
        return send_error(res, 404, MatrixError::not_found());
    }

    auto& room_id = match.params["roomId"];
    if (!store_.is_room_member(room_id, *user_id)) {
        return send_error(res, 403, MatrixError::forbidden("Not a member of this room"));
    }

    PermissionsEngine perms(store_, config_);
    if (!perms.can(*user_id, room_id, permission::kViewChannel)) {
        return send_error(res, 403, MatrixError::forbidden("No access to this channel"));
    }

    // Parse query params
    std::string dir = "b";
    if (req.has_param("dir")) dir = req.get_param_value("dir");

    int limit = limits::kDefaultMessagesLimit;
    if (req.has_param("limit")) {
        limit = std::min(std::stoi(req.get_param_value("limit")), limits::kMaxMessagesLimit);
    }

    std::optional<std::string> from;
    if (req.has_param("from")) from = req.get_param_value("from");

    auto events = store_.get_room_events(room_id, limit, dir, from);

    MessagesResponse msg_resp;
    msg_resp.chunk = std::move(events);
    if (from) msg_resp.start = *from;

    json resp;
    to_json(resp, msg_resp);
    res.set_content(resp.dump(), "application/json");
}

void EventHandler::handle_read_marker(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        return send_error(res, 401, MatrixError::missing_token());
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/read_marker", req.path);
    if (!match.matched) {
        return send_error(res, 404, MatrixError::not_found());
    }

    auto& room_id = match.params["roomId"];
    if (!store_.is_room_member(room_id, *user_id)) {
        return send_error(res, 403, MatrixError::forbidden("Not a member of this room"));
    }

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        return send_error(res, 400, MatrixError::bad_json());
    }

    int64_t pos = 0;
    if (body.contains("last_read_pos") && body["last_read_pos"].is_number_integer()) {
        pos = body["last_read_pos"].get<int64_t>();
    } else if (body.contains("m.fully_read") && body["m.fully_read"].is_string()) {
        pos = store_.get_room_max_stream_position(room_id);
    } else {
        pos = store_.get_room_max_stream_position(room_id);
    }

    store_.set_read_marker(*user_id, room_id, pos);
    sync_engine_.notify_new_event();

    res.set_content("{}", "application/json");
}

void EventHandler::handle_redact(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        return send_error(res, 401, MatrixError::missing_token());
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}", req.path);
    if (!match.matched) {
        return send_error(res, 404, MatrixError::not_found());
    }

    auto& room_id = match.params["roomId"];
    auto& target_event_id = match.params["eventId"];

    if (!store_.is_room_member(room_id, *user_id)) {
        return send_error(res, 403, MatrixError::forbidden("Not a member of this room"));
    }

    PermissionsEngine perms(store_, config_);
    auto user_perms = perms.compute(*user_id, room_id);
    if (!permission::has(user_perms, permission::kViewChannel)) {
        return send_error(res, 403, MatrixError::forbidden("No access to this channel"));
    }

    // Self-redact always allowed; redacting others requires MANAGE_MESSAGES.
    // Look up the target event's sender.
    auto events = store_.get_room_events(room_id, 1, "b", std::nullopt);
    // Use get_state_event-style lookup by event id — fall back to scanning.
    // The store doesn't expose get_event_by_id, so we query sqlite directly.
    auto target = store_.get_event_by_id(target_event_id);
    if (!target || target->room_id != room_id) {
        return send_error(res, 404, MatrixError::not_found("Target event not found in this room"));
    }
    const bool is_self = target->sender == *user_id;
    if (!is_self && !permission::has(user_perms, permission::kManageMessages)) {
        return send_error(res, 403, MatrixError::forbidden("You can only redact your own messages"));
    }

    json body = json::object();
    if (!req.body.empty()) {
        try { body = json::parse(req.body); } catch (...) {
            return send_error(res, 400, MatrixError::bad_json());
        }
    }

    json content = json::object();
    content["redacts"] = target_event_id;
    if (body.contains("reason") && body["reason"].is_string()) {
        content["reason"] = body["reason"];
    }

    auto event_id = generate_event_id(config_.server_name);
    store_.insert_event(event_id, room_id, *user_id,
                        std::string(event_type::kRoomRedaction),
                        std::nullopt, content.dump(), now_ms());
    sync_engine_.notify_new_event();

    res.set_content(json{{"event_id", event_id}}.dump(), "application/json");
}

} // namespace bsfchat
