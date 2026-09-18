#include "api/ProfileHandler.h"
#include "audit/AuditLog.h"
#include "auth/Permissions.h"
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

// Server scope for PermissionsEngine — see the same constant in RoomHandler.cpp.
// A nickname is one value per server, so evaluating it against a room would let a
// per-channel override hand out a server-wide capability.
const std::string kServerScope;
} // namespace

ProfileHandler::ProfileHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config)
    : store_(store), sync_engine_(sync_engine), config_(config) {}

void ProfileHandler::handle_get_profile(const httplib::Request& req, httplib::Response& res) {
    auto match = match_route("/_matrix/client/v3/profile/{userId}", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    const auto& user_id = match.params.at("userId");

    if (!store_.user_exists(user_id)) {
        res.status = 404;
        res.set_content(MatrixError::not_found("User not found").to_json().dump(), "application/json");
        return;
    }

    json resp;
    auto display_name = store_.get_display_name(user_id);
    auto avatar_url = store_.get_avatar_url(user_id);

    if (display_name) resp["displayname"] = *display_name;
    if (avatar_url) resp["avatar_url"] = *avatar_url;
    // `displayname` stays the GLOBAL name — this is the profile, and a client
    // settings screen editing the global name must not be handed the nickname to
    // save back over it. The nickname is reported separately so a client can show
    // both and render the nickname in preference where it renders people.
    if (auto nick = store_.get_nickname(user_id)) resp[kNicknameContentKey] = *nick;
    // Bot-ness, so a client can badge the account wherever it renders a person.
    //
    // On the PROFILE rather than in new membership state, which was the other
    // option. Bot-ness is a property of the account, not of a membership: state
    // would have to be written into every room the bot is in, backfilled into
    // rooms it joined before this existed, and would still be absent in any room
    // the client has not synced — so "is this a bot" would have a different
    // answer depending on where you asked. The profile is one fact in one place,
    // and a client already fetches it to render a name and an avatar.
    //
    // Unauthenticated-readable, like the rest of this endpoint. That is fine:
    // bot-ness is not a secret, it is a label the whole point of which is to be
    // shown to everyone who sees the account.
    if (store_.is_bot(user_id)) resp[std::string(bot::kProfileKey)] = true;

    res.set_content(resp.dump(), "application/json");
}

void ProfileHandler::handle_get_displayname(const httplib::Request& req, httplib::Response& res) {
    auto match = match_route("/_matrix/client/v3/profile/{userId}/displayname", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    const auto& user_id = match.params.at("userId");

    if (!store_.user_exists(user_id)) {
        res.status = 404;
        res.set_content(MatrixError::not_found("User not found").to_json().dump(), "application/json");
        return;
    }

    json resp;
    auto display_name = store_.get_display_name(user_id);
    if (display_name) resp["displayname"] = *display_name;

    res.set_content(resp.dump(), "application/json");
}

void ProfileHandler::handle_put_displayname(const httplib::Request& req, httplib::Response& res) {
    auto match = match_route("/_matrix/client/v3/profile/{userId}/displayname", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    const auto& target_user_id = match.params.at("userId");

    // Authenticate
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
        return;
    }

    // Only allow updating own profile
    if (*user_id != target_user_id) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Cannot set displayname for other users").to_json().dump(), "application/json");
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

    if (!body.contains("displayname") || !body["displayname"].is_string()) {
        res.status = 400;
        res.set_content(MatrixError::bad_json("Missing displayname field").to_json().dump(), "application/json");
        return;
    }

    store_.set_display_name(*user_id, body["displayname"].get<std::string>());
    broadcastMemberUpdate(*user_id);

    get_logger()->info("User {} updated display name", *user_id);
    res.set_content("{}", "application/json");
}

void ProfileHandler::handle_get_avatar_url(const httplib::Request& req, httplib::Response& res) {
    auto match = match_route("/_matrix/client/v3/profile/{userId}/avatar_url", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    const auto& user_id = match.params.at("userId");

    if (!store_.user_exists(user_id)) {
        res.status = 404;
        res.set_content(MatrixError::not_found("User not found").to_json().dump(), "application/json");
        return;
    }

    json resp;
    auto avatar_url = store_.get_avatar_url(user_id);
    if (avatar_url) resp["avatar_url"] = *avatar_url;

    res.set_content(resp.dump(), "application/json");
}

void ProfileHandler::handle_put_avatar_url(const httplib::Request& req, httplib::Response& res) {
    auto match = match_route("/_matrix/client/v3/profile/{userId}/avatar_url", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    const auto& target_user_id = match.params.at("userId");

    // Authenticate
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
        return;
    }

    // Only allow updating own profile
    if (*user_id != target_user_id) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Cannot set avatar_url for other users").to_json().dump(), "application/json");
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

    if (!body.contains("avatar_url") || !body["avatar_url"].is_string()) {
        res.status = 400;
        res.set_content(MatrixError::bad_json("Missing avatar_url field").to_json().dump(), "application/json");
        return;
    }

    store_.set_avatar_url(*user_id, body["avatar_url"].get<std::string>());
    broadcastMemberUpdate(*user_id);

    get_logger()->info("User {} updated avatar URL", *user_id);
    res.set_content("{}", "application/json");
}

void ProfileHandler::handle_get_nickname(const httplib::Request& req, httplib::Response& res) {
    auto match = match_route("/_matrix/client/v3/profile/{userId}/nickname", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    // Reading a nickname needs no permission: it is already visible in the
    // member events of every channel the reader shares with its owner. Gating the
    // read while leaving the mirror public would be theatre.
    const auto& user_id = match.params.at("userId");
    if (!store_.user_exists(user_id)) {
        res.status = 404;
        res.set_content(MatrixError::not_found("User not found").to_json().dump(), "application/json");
        return;
    }

    // Explicitly an object, because the no-nickname case is the COMMON one here
    // and a default-constructed json dumps as bare `null` when no key is ever
    // assigned. A client doing the obvious thing with the body — reading a key
    // off it — gets a type error rather than "absent", so the absence has to be
    // spelled as an empty object.
    json resp = json::object();
    if (auto nick = store_.get_nickname(user_id)) resp["nickname"] = *nick;
    res.set_content(resp.dump(), "application/json");
}

void ProfileHandler::handle_put_nickname(const httplib::Request& req, httplib::Response& res) {
    auto match = match_route("/_matrix/client/v3/profile/{userId}/nickname", req.path);
    if (!match.matched) {
        res.status = 404;
        res.set_content(MatrixError::not_found().to_json().dump(), "application/json");
        return;
    }

    const auto& target_user_id = match.params.at("userId");

    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(), "application/json");
        return;
    }

    if (!store_.user_exists(target_user_id)) {
        res.status = 404;
        res.set_content(MatrixError::not_found("User not found").to_json().dump(), "application/json");
        return;
    }

    const bool is_self = (*user_id == target_user_id);

    // Both checks are at SERVER scope. Following Discord exactly, the two flags
    // are not a hierarchy: MANAGE_NICKNAMES lets you rename other people and does
    // NOT imply the right to rename yourself, so a moderator whose role lacks
    // CHANGE_NICKNAME cannot set their own. ADMINISTRATOR short-circuits both
    // inside PermissionsEngine::compute, so no separate case is needed here.
    PermissionsEngine perms(store_, config_);
    if (is_self) {
        if (!perms.can(*user_id, kServerScope, permission::kChangeNickname)) {
            res.status = 403;
            res.set_content(MatrixError::forbidden(
                "Insufficient permissions to change your nickname").to_json().dump(),
                "application/json");
            return;
        }
    } else {
        if (!perms.can(*user_id, kServerScope, permission::kManageNicknames)) {
            res.status = 403;
            res.set_content(MatrixError::forbidden(
                "Insufficient permissions to change other members' nicknames").to_json().dump(),
                "application/json");
            return;
        }
        // The same rank check kick and ban use. Renaming someone is a visible act
        // of authority over them: a moderator who cannot kick an admin must not be
        // able to relabel one either. Not applied to self — outranks() is a strict
        // comparison, so a user never outranks themselves.
        if (!perms.outranks(*user_id, target_user_id)) {
            res.status = 403;
            res.set_content(MatrixError::forbidden(
                "Cannot change the nickname of a user with equal or higher role").to_json().dump(),
                "application/json");
            return;
        }
    }

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        res.status = 400;
        res.set_content(MatrixError::bad_json().to_json().dump(), "application/json");
        return;
    }

    // Absent, null, or an all-whitespace string all mean CLEAR. An empty nickname
    // is never storable — it would render as a nameless member.
    const bool has_value = body.contains("nickname") && !body["nickname"].is_null();
    if (has_value && !body["nickname"].is_string()) {
        res.status = 400;
        res.set_content(MatrixError::bad_json("nickname must be a string or null").to_json().dump(),
                        "application/json");
        return;
    }

    const auto previous = store_.get_nickname(target_user_id);
    std::optional<std::string> next;

    // A value that is blank (or only whitespace) is a CLEAR, not a validation
    // failure — the client's "reset nickname" affordance is an emptied field, and
    // making that a 400 would mean the only way to remove a nickname is a
    // different request shape.
    if (has_value && !is_blank_nickname(body["nickname"].get<std::string>())) {
        auto check = validate_nickname(body["nickname"].get<std::string>(), target_user_id,
                                       config_, store_);
        if (!check.ok) {
            res.status = 400;
            res.set_content(MatrixError::bad_json(check.error).to_json().dump(),
                            "application/json");
            return;
        }
        next = check.normalised;
    }

    store_.set_nickname(target_user_id, next);
    broadcastMemberUpdate(target_user_id);

    // A moderator renaming someone else is a moderation action and belongs in the
    // audit log next to the kick and ban it sits alongside in the UI. A user
    // renaming themselves is not, matching the existing rule that leaving a
    // channel yourself is not audited.
    if (!is_self) {
        audit_nickname_change(store_, *user_id, target_user_id, previous, next);
    }

    get_logger()->info("User {} set nickname of {} to '{}'", *user_id, target_user_id,
                       next ? *next : std::string("(cleared)"));
    res.set_content("{}", "application/json");
}

void ProfileHandler::broadcastMemberUpdate(const std::string& user_id)
{
    // Re-emit m.room.member state event in every joined room with the
    // current profile so all connected clients see the name/avatar change
    // on their next sync.
    //
    // This is also what makes a server-wide nickname reach every channel, and it
    // is why the nickname cannot live in room state alone: this loop overwrites
    // the displayname of every joined room from the profile, so a nickname stored
    // only in a member event would be erased here by an unrelated avatar change.
    // member_event_content reads the authoritative row, so the rewrite preserves
    // it instead.
    auto rooms = store_.get_joined_rooms(user_id);
    auto content = member_event_content(store_, user_id, std::string(membership::kJoin));

    for (const auto& room_id : rooms) {
        auto event_id = generate_event_id(config_.server_name);
        // This rewrite REPLACES the member event, so anything the original
        // carried that isn't rebuilt here is erased. `is_direct` is the DM
        // marker clients classify a room by; without this, renaming yourself
        // once would turn both participants' DM back into a plain channel.
        auto room_content = content;
        if (store_.is_direct_room(room_id)) room_content["is_direct"] = true;
        store_.insert_event(event_id, room_id, user_id,
                            std::string(event_type::kRoomMember),
                            user_id, room_content.dump(), now_ms());
    }
    if (!rooms.empty()) sync_engine_.notify_new_event();
}

} // namespace bsfchat
