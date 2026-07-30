#include "api/RoomHandler.h"
#include "audit/AuditLog.h"
#include "auth/AutoJoin.h"
#include "auth/Permissions.h"
#include "auth/RoleBootstrap.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "http/Middleware.h"
#include "http/Router.h"
#include "identity/Nickname.h"
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

// The room_id to pass to PermissionsEngine for a SERVER-scoped check. Named
// rather than spelled `""` at each call site because the difference between
// `room_id` and `""` in a perms.can() call is the entire difference between "a
// per-channel override can grant this" and "only a role can" — and that is not
// a distinction an empty string argument makes visible to a reader.
const std::string kServerScope;

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

bool is_category_room(SqliteStore& store, const std::string& room_id) {
    auto ev = store.get_state_event(room_id, std::string(event_type::kRoomType), "");
    if (!ev) return false;
    return ev->content.data.value("type", "") == "category";
}

// Membership alone is NOT authorization here: everyone is force-joined into
// every public room, so a user whose VIEW_CHANNEL was explicitly denied for a
// channel was still a joined member and could read its name, topic and full
// member list. Categories bypass the check to match SyncEngine, which lets the
// sidebar render the container node even when its children are hidden.
bool can_read_room(SqliteStore& store, const Config& config,
                   const std::string& user_id, const std::string& room_id) {
    if (!store.is_room_member(room_id, user_id)) return false;
    if (is_category_room(store, room_id)) return true;
    PermissionsEngine perms(store, config);
    return perms.can(user_id, room_id, permission::kViewChannel);
}

} // namespace

RoomHandler::RoomHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config)
    : store_(store), sync_engine_(sync_engine), config_(config) {}

std::string RoomHandler::emit_state_event(const std::string& room_id, const std::string& sender,
                                           const std::string& event_type, const std::string& state_key,
                                           const json& content) {
    auto event_id = generate_event_id(config_.server_name);
    store_.insert_event(event_id, room_id, sender, event_type, state_key, content.dump(), now_ms());
    sync_engine_.notify_new_event();
    return event_id;
}

void RoomHandler::handle_create_room(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
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

    // Direct messages are a per-user capability, not channel management: any
    // authenticated user may open a DM. Everything else — channels and
    // categories — is server structure and requires MANAGE_CHANNELS.
    //
    // This endpoint previously had NO authorization check at all, so any
    // authenticated user (including a freshly self-registered one) could
    // create channels; each public channel then force-joined the entire user
    // base via auto_join_all_users, emitting a membership event per user per
    // channel — an amplification primitive.
    const bool is_direct = room_req.is_direct.value_or(false);
    if (!is_direct) {
        // Server-scope check (empty room_id): a new room has no channel
        // context yet, so per-channel overrides must not apply.
        PermissionsEngine perms(store_, config_);
        if (!perms.can(*user_id, "", permission::kManageChannels)) {
            res.status = 403;
            res.set_content(MatrixError::forbidden(
                "Insufficient permissions to create channels").to_json().dump(),
                "application/json");
            return;
        }
    }

    auto room_id = generate_room_id(config_.server_name);
    store_.create_room(room_id, *user_id, is_direct);

    // Emit initial state events
    emit_state_event(room_id, *user_id, std::string(event_type::kRoomCreate), "",
                     json{{"creator", *user_id}, {"room_version", "10"}});

    // Creator joins — include their current display name + avatar so
    // clients don't need a separate profile fetch for the first sender.
    store_.set_membership(room_id, *user_id, std::string(membership::kJoin));
    emit_state_event(room_id, *user_id, std::string(event_type::kRoomMember), *user_id,
                     member_event_content(store_, *user_id, std::string(membership::kJoin)));

    // Set join rules.
    // Discord-like default: rooms are public unless explicitly marked private
    // (or the room is a category, which doesn't get auto-join anyway).
    // Only mark as invite-only if the client explicitly set visibility="private".
    // A direct room is always invite-only, whatever the client asked for.
    std::string visibility = body.value("visibility", std::string("public"));
    std::string join_rule_val = (is_direct || visibility == "private" || visibility == "invite")
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

    // Pull in anyone named in `invite`. The DM flow depends on this: a direct
    // room is invite-only, and it used to only reach the peer because the
    // room was (wrongly) public and the auto-join sweep dragged everyone in.
    //
    // SyncResponse carries joined rooms only — there is no invite delivery
    // channel — so members of a direct room are joined outright. Non-direct
    // rooms keep plain invite semantics, matching handle_invite.
    for (const auto& invitee : room_req.invite) {
        if (invitee == *user_id) continue;
        if (!store_.user_exists(invitee)) continue;

        const auto state = is_direct ? membership::kJoin : membership::kInvite;
        store_.set_membership(room_id, invitee, std::string(state));

        // member_event_content fills profile fields for join AND invite; the
        // previous code filled them only for the direct-room join, so a plain
        // invite carried no name. Both now carry the effective name, which is what
        // the invitee's nickname makes it.
        emit_state_event(room_id, *user_id, std::string(event_type::kRoomMember), invitee,
                         member_event_content(store_, invitee, std::string(state)));
    }

    // Auto-join all existing users if this is a public, non-category,
    // non-direct room so everyone on the server sees the new channel by
    // default.
    if (!is_direct && join_rule_val == join_rule::kPublic && !body.value("is_category", false)) {
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
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
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

    // A direct room is never joinable by request, whatever its join_rules
    // event says. Databases that ran the old boot-time backfill may still
    // carry a stale join_rule="public" on DM rooms.
    if (store_.is_direct_room(room_id) && !store_.is_room_member(room_id, *user_id)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Cannot join a direct message room").to_json().dump(),
                        "application/json");
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

    auto join_content = member_event_content(store_, *user_id, std::string(membership::kJoin));
    emit_state_event(room_id, *user_id, std::string(event_type::kRoomMember), *user_id,
                     join_content);

    res.set_content(json{{"room_id", room_id}}.dump(), "application/json");
    get_logger()->info("User {} joined room {}", *user_id, room_id);
}

void RoomHandler::handle_delete_room(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }
    auto& room_id = match.params["roomId"];
    if (!store_.room_exists(room_id)) {
        res.status = 404;
        res.set_content(MatrixError::not_found("Room not found").to_json().dump(), "application/json");
        return;
    }

    PermissionsEngine perms(store_, config_);
    if (!perms.can(*user_id, room_id, permission::kManageChannels)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Insufficient permissions to delete this channel").to_json().dump(), "application/json");
        return;
    }

    // Audited BEFORE the deletion, and this ordering is load-bearing: the record
    // captures the channel's name, type, parent category and member count, none of
    // which exist a moment later. It is also why the audit log cannot live in room
    // events — delete_room hard-deletes every event in the room, so a record kept
    // there would delete itself along with the thing it documents.
    audit_room_deletion(store_, *user_id, room_id);

    store_.delete_room(room_id);
    // Wake long-polls so clients notice and drop the room on their next
    // sync (the server's VIEW_CHANNEL filter now trivially excludes it —
    // they're no longer a joined member of anything by that id).
    sync_engine_.notify_new_event();

    get_logger()->info("Room {} deleted by {}", room_id, *user_id);
    res.set_content("{}", "application/json");
}

void RoomHandler::handle_leave(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
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
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
        return;
    }

    auto rooms = store_.get_joined_rooms(*user_id);
    res.set_content(json{{"joined_rooms", rooms}}.dump(), "application/json");
}

void RoomHandler::handle_room_state(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/state", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    auto& room_id = match.params["roomId"];
    if (!can_read_room(store_, config_, *user_id, room_id)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("No access to this channel").to_json().dump(), "application/json");
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
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
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
    if (!can_read_room(store_, config_, *user_id, room_id)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("No access to this channel").to_json().dump(), "application/json");
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
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/members", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    auto& room_id = match.params["roomId"];
    if (!can_read_room(store_, config_, *user_id, room_id)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("No access to this channel").to_json().dump(), "application/json");
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
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
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
    // SERVER scope (empty room_id). Kicking is a server-wide capability, as in
    // Discord: there is no per-channel kick, and no UI to grant one. Evaluating
    // it against `room_id` meant a per-channel override that allowed
    // KICK_MEMBERS in one channel conferred the ability to kick there — a grant
    // nothing in the product could intentionally make, and one an operator
    // editing an unrelated channel's overrides would not expect to be handing
    // out. See PermissionsEngine::compute: an empty room_id returns before any
    // channel override is applied.
    if (!perms.can(*user_id, kServerScope, permission::kKickMembers)) {
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

    const auto previous_membership = store_.get_membership(room_id, target_user);

    store_.set_membership(room_id, target_user, std::string(membership::kLeave));
    json member_content = {{"membership", membership::kLeave}};
    if (!reason.empty()) member_content["reason"] = reason;
    emit_state_event(room_id, *user_id, std::string(event_type::kRoomMember), target_user, member_content);

    audit_membership_change(store_, *user_id, room_id, target_user, previous_membership,
                            std::string(membership::kLeave), reason);

    res.set_content("{}", "application/json");
    get_logger()->info("User {} kicked {} from room {}", *user_id, target_user, room_id);
}

void RoomHandler::handle_ban(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
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
    // SERVER scope — see handle_kick. A ban is server-wide in intent (the client
    // applies one by looping every room), so it must not be unlockable by a
    // per-channel override.
    if (!perms.can(*user_id, kServerScope, permission::kBanMembers)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Insufficient permissions to ban").to_json().dump(), "application/json");
        return;
    }
    if (!perms.outranks(*user_id, target_user)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Cannot ban a user with equal or higher role").to_json().dump(), "application/json");
        return;
    }

    const auto previous_membership = store_.get_membership(room_id, target_user);

    store_.set_membership(room_id, target_user, std::string(membership::kBan));
    json member_content = {{"membership", membership::kBan}};
    if (!reason.empty()) member_content["reason"] = reason;
    emit_state_event(room_id, *user_id, std::string(event_type::kRoomMember), target_user, member_content);

    audit_membership_change(store_, *user_id, room_id, target_user, previous_membership,
                            std::string(membership::kBan), reason);

    res.set_content("{}", "application/json");
    get_logger()->info("User {} banned {} from room {}", *user_id, target_user, room_id);
}

// POST /rooms/{roomId}/unban
//
// This endpoint did not exist. The shipped client has always called it — see
// MatrixClient::unbanUser, and ServerConnection::unbanFromServer which loops it
// over every room — so "unban" was a button that 404'd, and a ban was in practice
// permanent. It is added here because an audit trail for bans that cannot record
// the corresponding unban is a trail that reads as if nobody is ever forgiven.
//
// Gated on BAN_MEMBERS (per the Matrix spec: lifting a ban needs the permission
// that imposed it) plus the same hierarchy check as ban, so a moderator cannot
// undo an admin's ban.
void RoomHandler::handle_unban(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
        return;
    }

    auto match = match_route("/_matrix/client/v3/rooms/{roomId}/unban", req.path);
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
    // SERVER scope — must match handle_ban exactly. If unban were channel-scoped
    // while ban is server-scoped, a per-channel override would let someone lift
    // bans they could never have placed.
    if (!perms.can(*user_id, kServerScope, permission::kBanMembers)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Insufficient permissions to unban").to_json().dump(), "application/json");
        return;
    }
    if (!perms.outranks(*user_id, target_user)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Cannot unban a user with equal or higher role").to_json().dump(), "application/json");
        return;
    }

    const auto previous_membership = store_.get_membership(room_id, target_user);
    if (previous_membership != membership::kBan) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("User is not banned from this room").to_json().dump(),
                        "application/json");
        return;
    }

    // "leave", not "join": lifting a ban restores the user's ability to come back,
    // it does not decide for them that they have.
    store_.set_membership(room_id, target_user, std::string(membership::kLeave));
    json member_content = {{"membership", membership::kLeave}};
    if (!reason.empty()) member_content["reason"] = reason;
    emit_state_event(room_id, *user_id, std::string(event_type::kRoomMember), target_user, member_content);

    audit_membership_change(store_, *user_id, room_id, target_user, previous_membership,
                            std::string(membership::kLeave), reason);

    res.set_content("{}", "application/json");
    get_logger()->info("User {} unbanned {} in room {}", *user_id, target_user, room_id);
}

void RoomHandler::handle_invite(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
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
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
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

    // Server-SCOPED state: these describe the whole server, not this channel.
    // Gating them on a per-channel permission check was a privilege-escalation
    // hole — a per-channel override granting MANAGE_ROLES in one unimportant
    // channel let that user rewrite every role on the server, including
    // granting themselves ADMINISTRATOR, because the role reader ignored
    // room_id entirely. The check below passes an empty room_id so channel
    // overrides cannot contribute.
    const bool is_server_scoped =
        evt_type == std::string(event_type::kServerRoles) ||
        evt_type == std::string(event_type::kMemberRoles);

    // Moderation-by-membership-write. This route will happily set another user's
    // m.room.member to "ban", which makes it a second, complete implementation of
    // POST /rooms/{id}/ban — so it has to be gated the same way, at SERVER scope.
    // While kick/ban were channel-scoped and this was too they at least agreed;
    // moving only the dedicated endpoints would have left this route as the
    // bypass, converting a per-channel KICK_MEMBERS override into a server-wide
    // ban primitive. Self-membership is excluded: it is handled below and is a
    // genuinely per-channel action (joining and leaving a channel).
    const bool is_member_moderation =
        evt_type == std::string(event_type::kRoomMember) && state_key != *user_id;

    // Map the state event type to the permission flag that gates it.
    permission::Flags required = permission::kManageChannels;
    if (is_server_scoped || evt_type == std::string(event_type::kChannelPermissions)) {
        required = permission::kManageRoles;
    } else if (evt_type == std::string(event_type::kServerInfo)) {
        required = permission::kManageServer;
    } else if (evt_type == std::string(event_type::kRoomMember)) {
        // Self-membership is handled separately below; anything targeting
        // another user goes through the kick/ban permission.
        required = permission::kKickMembers;
    }

    PermissionsEngine perms(store_, config_);
    // Two separate notions, deliberately not one flag: `is_server_scoped` also
    // decides WHERE the write lands (server_state vs room state), while this only
    // decides how the permission is evaluated. Member moderation is server-scoped
    // for permissions but still writes ordinary room state.
    const bool is_server_scoped_permission = is_server_scoped || is_member_moderation;
    const std::string perm_scope = is_server_scoped_permission ? kServerScope : room_id;

    json content;
    try {
        content = json::parse(req.body);
    } catch (...) {
        res.status = 400;
        res.set_content(MatrixError::bad_json().to_json().dump(), "application/json");
        return;
    }

    // Self-membership: a joined member may update their own m.room.member
    // event, but only to a membership the server recognises, and the profile
    // fields are filled in server-side. Previously this path mapped down to
    // VIEW_CHANNEL and wrote the client's body verbatim, so any member could
    // forge a `displayname` that every other client renders in member lists.
    if (evt_type == std::string(event_type::kRoomMember) && state_key == *user_id) {
        if (!perms.can(*user_id, room_id, permission::kViewChannel)) {
            res.status = 403;
            res.set_content(MatrixError::forbidden("No access to this channel").to_json().dump(),
                            "application/json");
            return;
        }
        const std::string requested = content.value("membership", "");
        if (requested != membership::kJoin && requested != membership::kLeave) {
            res.status = 403;
            res.set_content(MatrixError::forbidden(
                "Only join/leave may be set on your own membership").to_json().dump(),
                "application/json");
            return;
        }

        store_.set_membership(room_id, *user_id, requested);

        // Profile fields come from the server's own records, never from the
        // request body — that is the fix this branch already carried, and routing
        // it through member_event_content keeps it true while adding the nickname.
        // A user CAN change their rendered name here, but only by going through
        // PUT /profile/{me}/nickname, which is gated on CHANGE_NICKNAME.
        auto member_content = member_event_content(store_, *user_id, requested);
        auto member_event_id =
            emit_state_event(room_id, *user_id, evt_type, state_key, member_content);
        res.set_content(json{{"event_id", member_event_id}}.dump(), "application/json");
        return;
    }

    if (!perms.can(*user_id, perm_scope, required)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Insufficient permissions for this state event").to_json().dump(), "application/json");
        return;
    }

    // The dedicated kick/ban/unban endpoints all refuse to act on a user of equal
    // or higher rank. This route performs the same transitions and did not check,
    // so a moderator could ban an admin here after being refused at POST
    // /rooms/{id}/ban. Closing the scope hole without closing this one would have
    // left the bypass intact in a different direction.
    if (is_member_moderation && !state_key.empty() && !perms.outranks(*user_id, state_key)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden(
            "Cannot change the membership of a user with equal or higher role").to_json().dump(),
            "application/json");
        return;
    }

    if (is_server_scoped) {
        // Authoritative write lands in server_state; the room event is only a
        // mirror so clients still learn about it through /sync. Role definition and
        // role assignment changes are audited inside write_server_scoped_state,
        // which is the choke point they all share.
        write_server_scoped_state(store_, config_, evt_type, state_key, content.dump(),
                                  room_id, *user_id);
        sync_engine_.notify_new_event();
        auto mirrored = store_.get_state_event(room_id, evt_type, state_key);
        res.set_content(
            json{{"event_id", mirrored ? mirrored->event_id : std::string()}}.dump(),
            "application/json");
        return;
    }

    // The state either side of this write, captured before it is superseded.
    // Per-channel overrides are ordinary room state, so unlike the server-scoped
    // types above there is no shared write function to hook — the capture has to
    // happen here, and it has to happen before the new event is inserted.
    const bool is_channel_override = evt_type == std::string(event_type::kChannelPermissions);
    // This is also a moderator acting on somebody ELSE's membership: the
    // self-membership case returned above. Auditing it matters because it is a
    // second, entirely separate route to a ban — a ban placed through here would
    // otherwise be invisible while the same ban through POST /rooms/{id}/ban was
    // recorded.
    // The empty-state_key guard matters: this route also matches
    // /state/m.room.member with no state key at all, which names no target. A
    // record whose target_user is "" would be an audit entry nobody can act on.
    const bool is_other_membership =
        evt_type == std::string(event_type::kRoomMember) && !state_key.empty();

    std::optional<std::string> previous_state;
    std::string previous_membership;
    if (is_channel_override) {
        auto existing = store_.get_state_event(room_id, evt_type, state_key);
        if (existing) previous_state = existing->content.data.dump();
    } else if (is_other_membership) {
        previous_membership = store_.get_membership(room_id, state_key);
    }

    // Echo back the id that was actually stored — this used to generate a
    // second, unrelated id and hand the client an event_id not in the database.
    auto event_id = emit_state_event(room_id, *user_id, evt_type, state_key, content);

    if (is_channel_override) {
        audit_channel_override_change(store_, *user_id, room_id, state_key, previous_state,
                                      content.dump());
    } else if (is_other_membership) {
        audit_membership_change(store_, *user_id, room_id, state_key, previous_membership,
                                content.value("membership", ""), content.value("reason", ""));
    }

    res.set_content(json{{"event_id", event_id}}.dump(), "application/json");
}

void RoomHandler::handle_move_channel(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
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
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
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
