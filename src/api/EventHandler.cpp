#include "api/EventHandler.h"
#include "auth/PowerLevels.h"
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

#include <nlohmann/json.hpp>
#include <chrono>

namespace bsfchat {

using json = nlohmann::json;

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

} // namespace

EventHandler::EventHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config)
    : store_(store), sync_engine_(sync_engine), config_(config) {}

void EventHandler::handle_send_event(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    // Match: PUT /rooms/{roomId}/send/{eventType}/{txnId}
    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    auto& room_id = match.params["roomId"];
    auto& evt_type = match.params["eventType"];

    if (!store_.is_room_member(room_id, *user_id)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Not a member of this room").to_json().dump(), "application/json");
        return;
    }

    // Check power levels for sending this event type
    auto pl_event = store_.get_state_event(room_id, std::string(event_type::kRoomPowerLevels), "");
    if (pl_event) {
        PowerLevelsContent pl;
        from_json(pl_event->content.data, pl);
        PowerLevelChecker checker(pl);

        if (!checker.canSendEvent(*user_id, evt_type, /*is_state=*/false)) {
            res.status = 403;
            res.set_content(MatrixError::forbidden("Insufficient power level to send this event").to_json().dump(), "application/json");
            return;
        }
    }

    json content;
    try {
        content = json::parse(req.body);
    } catch (...) {
        res.status = 400;
        res.set_content(MatrixError::bad_json().to_json().dump(), "application/json");
        return;
    }

    auto event_id = generate_event_id(config_.server_name);
    store_.insert_event(event_id, room_id, *user_id, evt_type, std::nullopt, content.dump(), now_ms());
    sync_engine_.notify_new_event();

    res.set_content(json{{"event_id", event_id}}.dump(), "application/json");
}

void EventHandler::handle_room_messages(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/messages", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    auto& room_id = match.params["roomId"];
    if (!store_.is_room_member(room_id, *user_id)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Not a member of this room").to_json().dump(), "application/json");
        return;
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
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/read_marker", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    auto& room_id = match.params["roomId"];
    if (!store_.is_room_member(room_id, *user_id)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Not a member of this room").to_json().dump(), "application/json");
        return;
    }

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        res.status = 400;
        res.set_content(MatrixError::bad_json().to_json().dump(), "application/json");
        return;
    }

    // Accept either explicit last_read_pos, or an event_id we look up.
    int64_t pos = 0;
    if (body.contains("last_read_pos") && body["last_read_pos"].is_number_integer()) {
        pos = body["last_read_pos"].get<int64_t>();
    } else if (body.contains("m.fully_read") && body["m.fully_read"].is_string()) {
        // Matrix spec shape: { "m.fully_read": "$event_id", "m.read": "$event_id" }
        // We don't currently look these up; default to the current max for the room.
        pos = store_.get_room_max_stream_position(room_id);
    } else {
        // No usable body — treat as "mark all read now".
        pos = store_.get_room_max_stream_position(room_id);
    }

    store_.set_read_marker(*user_id, room_id, pos);
    // Wake long-poll syncs so the count updates without waiting.
    sync_engine_.notify_new_event();

    res.set_content("{}", "application/json");
}

} // namespace bsfchat
