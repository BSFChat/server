#include "api/VoiceHandler.h"
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

void emit_state_event(SqliteStore& store, SyncEngine& sync_engine, const std::string& server_name,
                      const std::string& room_id, const std::string& sender,
                      const std::string& event_type, const std::string& state_key,
                      const json& content) {
    auto event_id = generate_event_id(server_name);
    store.insert_event(event_id, room_id, sender, event_type, state_key, content.dump(), now_ms());
    sync_engine.notify_new_event();
}

} // namespace

VoiceHandler::VoiceHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config)
    : store_(store), sync_engine_(sync_engine), config_(config) {}

void VoiceHandler::handle_voice_join(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/voice/join", req.path);
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

    // Check if room is voice-capable
    auto voice_state = store_.get_state_event(room_id, std::string(event_type::kRoomVoice), "");
    if (!voice_state) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Room is not voice-capable").to_json().dump(), "application/json");
        return;
    }

    VoiceChannelContent voice_channel;
    from_json(voice_state->content.data, voice_channel);
    if (!voice_channel.enabled) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Voice is disabled in this room").to_json().dump(), "application/json");
        return;
    }

    // Check max participants if set
    if (voice_channel.max_participants > 0) {
        // Count active members
        auto state_events = store_.get_state_events(room_id);
        int active_count = 0;
        for (const auto& ev : state_events) {
            if (ev.type == std::string(event_type::kCallMember)) {
                if (ev.content.data.value("active", false)) {
                    active_count++;
                }
            }
        }
        if (active_count >= voice_channel.max_participants) {
            res.status = 403;
            res.set_content(MatrixError::forbidden("Voice channel is full").to_json().dump(), "application/json");
            return;
        }
    }

    // Parse optional device_id from body
    std::string device_id;
    if (!req.body.empty()) {
        try {
            auto body = json::parse(req.body);
            device_id = body.value("device_id", "");
        } catch (...) {}
    }

    // Set the user's m.call.member state to active
    VoiceMemberContent member;
    member.active = true;
    member.muted = false;
    member.deafened = false;
    member.device_id = device_id;
    member.joined_at = now_ms();

    json member_json;
    to_json(member_json, member);
    emit_state_event(store_, sync_engine_, config_.server_name,
                     room_id, *user_id, std::string(event_type::kCallMember), *user_id, member_json);

    // Gather list of other active voice members
    auto state_events = store_.get_state_events(room_id);
    json members_arr = json::array();
    for (const auto& ev : state_events) {
        if (ev.type == std::string(event_type::kCallMember) && ev.state_key && *ev.state_key != *user_id) {
            if (ev.content.data.value("active", false)) {
                members_arr.push_back({
                    {"user_id", *ev.state_key},
                    {"muted", ev.content.data.value("muted", false)},
                    {"deafened", ev.content.data.value("deafened", false)},
                    {"device_id", ev.content.data.value("device_id", "")},
                });
            }
        }
    }

    res.set_content(json{{"members", members_arr}}.dump(), "application/json");
    get_logger()->info("User {} joined voice in room {}", *user_id, room_id);
}

void VoiceHandler::handle_voice_leave(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/voice/leave", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    auto& room_id = match.params["roomId"];

    // Set the user's m.call.member state to inactive
    VoiceMemberContent member;
    member.active = false;

    json member_json;
    to_json(member_json, member);
    emit_state_event(store_, sync_engine_, config_.server_name,
                     room_id, *user_id, std::string(event_type::kCallMember), *user_id, member_json);

    res.set_content("{}", "application/json");
    get_logger()->info("User {} left voice in room {}", *user_id, room_id);
}

void VoiceHandler::handle_voice_members(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/voice/members", req.path);
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

    auto state_events = store_.get_state_events(room_id);
    json members_arr = json::array();
    for (const auto& ev : state_events) {
        if (ev.type == std::string(event_type::kCallMember) && ev.state_key) {
            if (ev.content.data.value("active", false)) {
                members_arr.push_back({
                    {"user_id", *ev.state_key},
                    {"muted", ev.content.data.value("muted", false)},
                    {"deafened", ev.content.data.value("deafened", false)},
                    {"device_id", ev.content.data.value("device_id", "")},
                    {"joined_at", ev.content.data.value("joined_at", int64_t(0))},
                });
            }
        }
    }

    res.set_content(json{{"members", members_arr}}.dump(), "application/json");
}

void VoiceHandler::handle_voice_state(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/voice/state", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    auto& room_id = match.params["roomId"];

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        res.status = 400;
        res.set_content(MatrixError::bad_json().to_json().dump(), "application/json");
        return;
    }

    // Get current member state
    auto current = store_.get_state_event(room_id, std::string(event_type::kCallMember), *user_id);
    if (!current || !current->content.data.value("active", false)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Not in voice channel").to_json().dump(), "application/json");
        return;
    }

    // Update muted/deafened from request body, keep other fields
    auto updated = current->content.data;
    if (body.contains("muted")) updated["muted"] = body["muted"].get<bool>();
    if (body.contains("deafened")) updated["deafened"] = body["deafened"].get<bool>();

    emit_state_event(store_, sync_engine_, config_.server_name,
                     room_id, *user_id, std::string(event_type::kCallMember), *user_id, updated);

    res.set_content("{}", "application/json");
}

void VoiceHandler::handle_turn_server(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    json uris = json::array();
    if (!config_.voice.stun_uri.empty()) {
        uris.push_back(config_.voice.stun_uri);
    }
    if (!config_.voice.turn_uri.empty()) {
        uris.push_back(config_.voice.turn_uri);
    }

    json resp = {
        {"username", config_.voice.turn_username},
        {"password", config_.voice.turn_password},
        {"uris", uris},
        {"ttl", 86400},
        {"allow_p2p", config_.voice.allow_peer_to_peer},
    };

    res.set_content(resp.dump(), "application/json");
}

} // namespace bsfchat
