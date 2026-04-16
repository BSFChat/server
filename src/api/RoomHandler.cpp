#include "api/RoomHandler.h"
#include "auth/AutoJoin.h"
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

namespace bsfchat {

using json = nlohmann::json;

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

} // namespace

RoomHandler::RoomHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config)
    : store_(store), sync_engine_(sync_engine), config_(config) {}

void RoomHandler::emit_state_event(const std::string& room_id, const std::string& sender,
                                    const std::string& event_type, const std::string& state_key,
                                    const json& content) {
    auto event_id = generate_event_id(config_.server_name);
    store_.insert_event(event_id, room_id, sender, event_type, state_key, content.dump(), now_ms());
    sync_engine_.notify_new_event();
}

void RoomHandler::handle_create_room(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    json body;
    try {
        body = json::parse(req.body.empty() ? "{}" : req.body);
    } catch (...) {
        res.status = 400;
        res.set_content(MatrixError::bad_json().to_json().dump(), "application/json");
        return;
    }

    CreateRoomRequest room_req;
    from_json(body, room_req);

    auto room_id = generate_room_id(config_.server_name);
    store_.create_room(room_id, *user_id);

    // Emit initial state events
    emit_state_event(room_id, *user_id, std::string(event_type::kRoomCreate), "",
                     json{{"creator", *user_id}, {"room_version", "10"}});

    // Creator joins
    store_.set_membership(room_id, *user_id, std::string(membership::kJoin));
    emit_state_event(room_id, *user_id, std::string(event_type::kRoomMember), *user_id,
                     json{{"membership", membership::kJoin}});

    // Set join rules.
    // Discord-like default: rooms are public unless explicitly marked private
    // (or the room is a category, which doesn't get auto-join anyway).
    // Only mark as invite-only if the client explicitly set visibility="private".
    std::string visibility = body.value("visibility", std::string("public"));
    std::string join_rule_val = (visibility == "private" || visibility == "invite")
        ? std::string(join_rule::kInvite)
        : std::string(join_rule::kPublic);
    emit_state_event(room_id, *user_id, std::string(event_type::kRoomJoinRules), "",
                     json{{"join_rule", join_rule_val}});

    // Set room name if provided
    if (room_req.name) {
        emit_state_event(room_id, *user_id, std::string(event_type::kRoomName), "",
                         json{{"name", *room_req.name}});
    }

    // Set topic if provided
    if (room_req.topic) {
        emit_state_event(room_id, *user_id, std::string(event_type::kRoomTopic), "",
                         json{{"topic", *room_req.topic}});
    }

    // Note: we no longer emit m.room.power_levels. Permissions now flow from
    // server-wide roles (bsfchat.server.roles) and per-channel overrides
    // (bsfchat.channel.permissions). The creator is expected to already hold
    // an admin role via RoleBootstrap; if not, they'll be granted one at the
    // first server-settings interaction.

    // Set voice channel state if requested
    if (body.value("voice", false)) {
        VoiceChannelContent voice;
        voice.enabled = true;
        voice.max_participants = body.value("max_voice_participants", 0);
        json voice_json;
        to_json(voice_json, voice);
        emit_state_event(room_id, *user_id, std::string(event_type::kRoomVoice), "", voice_json);
    }

    // Emit bsfchat.room.type state event
    {
        std::string room_type;
        if (body.value("is_category", false)) {
            room_type = "category";
        } else if (body.value("voice", false)) {
            room_type = "voice";
        } else {
            room_type = "text";
        }
        emit_state_event(room_id, *user_id, std::string(event_type::kRoomType), "",
                         json{{"type", room_type}});
    }

    // Emit bsfchat.room.category if parent_id is provided
    if (body.contains("parent_id")) {
        auto parent_id = body["parent_id"].get<std::string>();
        if (!store_.room_exists(parent_id)) {
            res.status = 400;
            res.set_content(MatrixError::bad_json("Parent room does not exist").to_json().dump(), "application/json");
            return;
        }
        int order = body.value("sort_order", 0);
        emit_state_event(room_id, *user_id, std::string(event_type::kRoomCategory), "",
                         json{{"parent_id", parent_id}, {"order", order}});
    }

    // Default server roles are seeded once per server by RoleBootstrap —
    // we don't emit them on every category creation anymore.

    // Auto-join all existing users if this is a public, non-category room
    // so everyone on the server sees the new channel by default.
    if (join_rule_val == join_rule::kPublic && !body.value("is_category", false)) {
        auto_join_all_users(store_, sync_engine_, config_, room_id, *user_id);
    }

    CreateRoomResponse room_resp{.room_id = room_id};
    json resp;
    to_json(resp, room_resp);
    res.set_content(resp.dump(), "application/json");

    get_logger()->info("Room created: {} by {}", room_id, *user_id);
}

void RoomHandler::handle_join(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    // Extract room ID from path: /join/{roomIdOrAlias} or /rooms/{roomId}/join
    auto match = match_route("/_matrix/client/v3/join/{roomIdOrAlias}", req.path);
    std::string room_id;
    if (match.matched) {
        room_id = match.params["roomIdOrAlias"];
    } else {
        auto match2 = match_route("/_matrix/client/v3/rooms/{roomId}/join", req.path);
        if (match2.matched) {
            room_id = match2.params["roomId"];
        }
    }

    if (room_id.empty() || !store_.room_exists(room_id)) {
        res.status = 404;
        res.set_content(MatrixError::not_found("Room not found").to_json().dump(), "application/json");
        return;
    }

    // Check join rules
    auto join_rules = store_.get_state_event(room_id, std::string(event_type::kRoomJoinRules), "");
    if (join_rules) {
        auto rule = join_rules->content.data.value("join_rule", "invite");
        if (rule == "invite") {
            auto current_membership = store_.get_membership(room_id, *user_id);
            if (current_membership != "invite" && current_membership != "join") {
                res.status = 403;
                res.set_content(MatrixError::forbidden("This room requires an invite").to_json().dump(), "application/json");
                return;
            }
        }
    }

    store_.set_membership(room_id, *user_id, std::string(membership::kJoin));
    emit_state_event(room_id, *user_id, std::string(event_type::kRoomMember), *user_id,
                     json{{"membership", membership::kJoin}});

    res.set_content(json{{"room_id", room_id}}.dump(), "application/json");
    get_logger()->info("User {} joined room {}", *user_id, room_id);
}

void RoomHandler::handle_leave(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/leave", req.path);
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

    store_.set_membership(room_id, *user_id, std::string(membership::kLeave));
    emit_state_event(room_id, *user_id, std::string(event_type::kRoomMember), *user_id,
                     json{{"membership", membership::kLeave}});

    res.set_content("{}", "application/json");
}

void RoomHandler::handle_joined_rooms(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    auto rooms = store_.get_joined_rooms(*user_id);
    res.set_content(json{{"joined_rooms", rooms}}.dump(), "application/json");
}

void RoomHandler::handle_room_state(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/state", req.path);
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

    auto events = store_.get_state_events(room_id);
    json resp = json::array();
    for (const auto& ev : events) {
        json j;
        to_json(j, ev);
        resp.push_back(j);
    }
    res.set_content(resp.dump(), "application/json");
}

void RoomHandler::handle_room_state_event(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}", req.path);
    if (!match.matched) {
        // Try without state key
        match = match_route("/_matrix/client/v3/rooms/{roomId}/state/{eventType}", req.path);
        if (!match.matched) {
            res.status = 404;
            res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
            return;
        }
        match.params["stateKey"] = "";
    }

    auto& room_id = match.params["roomId"];
    if (!store_.is_room_member(room_id, *user_id)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Not a member of this room").to_json().dump(), "application/json");
        return;
    }

    auto event = store_.get_state_event(room_id, match.params["eventType"], match.params["stateKey"]);
    if (!event) {
        res.status = 404;
        res.set_content(MatrixError::not_found("State event not found").to_json().dump(), "application/json");
        return;
    }

    res.set_content(event->content.data.dump(), "application/json");
}

void RoomHandler::handle_room_members(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/members", req.path);
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

    auto members = store_.get_room_members(room_id);
    json chunk = json::array();
    for (const auto& [member_id, member_membership] : members) {
        chunk.push_back({
            {"type", event_type::kRoomMember},
            {"state_key", member_id},
            {"content", {{"membership", member_membership}}},
            {"sender", member_id},
            {"room_id", room_id},
        });
    }
    res.set_content(json{{"chunk", chunk}}.dump(), "application/json");
}

void RoomHandler::handle_kick(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/kick", req.path);
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

    if (!body.contains("user_id") || !body["user_id"].is_string()) {
        res.status = 400;
        res.set_content(MatrixError::bad_json("Missing user_id").to_json().dump(), "application/json");
        return;
    }

    auto target_user = body["user_id"].get<std::string>();
    auto reason = body.value("reason", "");

    PermissionsEngine perms(store_, config_);
    if (!perms.can(*user_id, room_id, permission::kKickMembers)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Insufficient permissions to kick").to_json().dump(), "application/json");
        return;
    }
    if (!perms.outranks(*user_id, target_user)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Cannot kick a user with equal or higher role").to_json().dump(), "application/json");
        return;
    }

    if (!store_.is_room_member(room_id, target_user)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("User is not in the room").to_json().dump(), "application/json");
        return;
    }

    store_.set_membership(room_id, target_user, std::string(membership::kLeave));
    json member_content = {{"membership", membership::kLeave}};
    if (!reason.empty()) member_content["reason"] = reason;
    emit_state_event(room_id, *user_id, std::string(event_type::kRoomMember), target_user, member_content);

    res.set_content("{}", "application/json");
    get_logger()->info("User {} kicked {} from room {}", *user_id, target_user, room_id);
}

void RoomHandler::handle_ban(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/ban", req.path);
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

    if (!body.contains("user_id") || !body["user_id"].is_string()) {
        res.status = 400;
        res.set_content(MatrixError::bad_json("Missing user_id").to_json().dump(), "application/json");
        return;
    }

    auto target_user = body["user_id"].get<std::string>();
    auto reason = body.value("reason", "");

    PermissionsEngine perms(store_, config_);
    if (!perms.can(*user_id, room_id, permission::kBanMembers)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Insufficient permissions to ban").to_json().dump(), "application/json");
        return;
    }
    if (!perms.outranks(*user_id, target_user)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Cannot ban a user with equal or higher role").to_json().dump(), "application/json");
        return;
    }

    store_.set_membership(room_id, target_user, std::string(membership::kBan));
    json member_content = {{"membership", membership::kBan}};
    if (!reason.empty()) member_content["reason"] = reason;
    emit_state_event(room_id, *user_id, std::string(event_type::kRoomMember), target_user, member_content);

    res.set_content("{}", "application/json");
    get_logger()->info("User {} banned {} from room {}", *user_id, target_user, room_id);
}

void RoomHandler::handle_invite(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/invite", req.path);
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

    if (!body.contains("user_id") || !body["user_id"].is_string()) {
        res.status = 400;
        res.set_content(MatrixError::bad_json("Missing user_id").to_json().dump(), "application/json");
        return;
    }

    auto target_user = body["user_id"].get<std::string>();

    PermissionsEngine perms(store_, config_);
    // Inviting piggybacks on MANAGE_CHANNELS for now — we don't have a separate flag.
    if (!perms.can(*user_id, room_id, permission::kManageChannels)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Insufficient permissions to invite").to_json().dump(), "application/json");
        return;
    }

    // Check target user is not already banned
    auto target_membership = store_.get_membership(room_id, target_user);
    if (target_membership == "ban") {
        res.status = 403;
        res.set_content(MatrixError::forbidden("User is banned from this room").to_json().dump(), "application/json");
        return;
    }

    store_.set_membership(room_id, target_user, std::string(membership::kInvite));
    emit_state_event(room_id, *user_id, std::string(event_type::kRoomMember), target_user,
                     json{{"membership", membership::kInvite}});

    res.set_content("{}", "application/json");
    get_logger()->info("User {} invited {} to room {}", *user_id, target_user, room_id);
}

void RoomHandler::handle_set_state(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}", req.path);
    if (!match.matched) {
        match = match_route("/_matrix/client/v3/rooms/{roomId}/state/{eventType}", req.path);
        if (!match.matched) {
            res.status = 404;
            res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
            return;
        }
        match.params["stateKey"] = "";
    }

    auto& room_id = match.params["roomId"];
    auto& evt_type = match.params["eventType"];
    auto& state_key = match.params["stateKey"];

    if (!store_.is_room_member(room_id, *user_id)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Not a member of this room").to_json().dump(), "application/json");
        return;
    }

    // Map the state event type to the permission flag that gates it.
    permission::Flags required = permission::kManageChannels;
    if (evt_type == std::string(event_type::kServerRoles) ||
        evt_type == std::string(event_type::kMemberRoles) ||
        evt_type == std::string(event_type::kChannelPermissions)) {
        required = permission::kManageRoles;
    } else if (evt_type == std::string(event_type::kServerInfo)) {
        required = permission::kManageServer;
    } else if (evt_type == std::string(event_type::kRoomMember)) {
        // Self-leave is always allowed; otherwise gate through kick/ban paths.
        required = permission::kKickMembers;
        if (state_key == *user_id) required = permission::kViewChannel; // effectively always allowed for joined members
    }

    PermissionsEngine perms(store_, config_);
    if (!perms.can(*user_id, room_id, required)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Insufficient permissions for this state event").to_json().dump(), "application/json");
        return;
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
    emit_state_event(room_id, *user_id, evt_type, state_key, content);

    res.set_content(json{{"event_id", event_id}}.dump(), "application/json");
}

void RoomHandler::handle_move_channel(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/category", req.path);
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

    PermissionsEngine perms(store_, config_);
    if (!perms.can(*user_id, room_id, permission::kManageChannels)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Insufficient permissions to move channels").to_json().dump(), "application/json");
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

    if (!body.contains("parent_id")) {
        res.status = 400;
        res.set_content(MatrixError::bad_json("Missing parent_id").to_json().dump(), "application/json");
        return;
    }

    // Handle null parent_id (uncategorize)
    if (body["parent_id"].is_null()) {
        emit_state_event(room_id, *user_id, std::string(event_type::kRoomCategory), "",
                         json{{"parent_id", ""}, {"order", 0}});
        res.set_content("{}", "application/json");
        return;
    }

    auto parent_id = body["parent_id"].get<std::string>();

    // Validate parent room exists
    if (!store_.room_exists(parent_id)) {
        res.status = 404;
        res.set_content(MatrixError::not_found("Parent room not found").to_json().dump(), "application/json");
        return;
    }

    // Validate parent is a category type
    auto type_event = store_.get_state_event(parent_id, std::string(event_type::kRoomType), "");
    if (!type_event || type_event->content.data.value("type", "") != "category") {
        res.status = 400;
        res.set_content(MatrixError::bad_json("Parent room is not a category").to_json().dump(), "application/json");
        return;
    }

    // Get existing order or default to 0
    int order = 0;
    auto existing = store_.get_state_event(room_id, std::string(event_type::kRoomCategory), "");
    if (existing) {
        order = existing->content.data.value("order", 0);
    }

    emit_state_event(room_id, *user_id, std::string(event_type::kRoomCategory), "",
                     json{{"parent_id", parent_id}, {"order", order}});

    res.set_content("{}", "application/json");
    get_logger()->info("Channel {} moved to category {} by {}", room_id, parent_id, *user_id);
}

void RoomHandler::handle_set_order(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(MatrixError::missing_token().to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/order", req.path);
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

    PermissionsEngine perms(store_, config_);
    if (!perms.can(*user_id, room_id, permission::kManageChannels)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Insufficient permissions to reorder channels").to_json().dump(), "application/json");
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

    if (!body.contains("order") || !body["order"].is_number_integer()) {
        res.status = 400;
        res.set_content(MatrixError::bad_json("Missing or invalid order").to_json().dump(), "application/json");
        return;
    }

    int new_order = body["order"].get<int>();

    // Get existing category state event
    auto existing = store_.get_state_event(room_id, std::string(event_type::kRoomCategory), "");
    std::string parent_id;
    if (existing) {
        parent_id = existing->content.data.value("parent_id", "");
    }

    emit_state_event(room_id, *user_id, std::string(event_type::kRoomCategory), "",
                     json{{"parent_id", parent_id}, {"order", new_order}});

    res.set_content("{}", "application/json");
    get_logger()->info("Channel {} order set to {} by {}", room_id, new_order, *user_id);
}

} // namespace bsfchat
