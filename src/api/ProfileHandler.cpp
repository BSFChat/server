#include "api/ProfileHandler.h"
#include "api/InputLimits.h"
#include "auth/MediaAccess.h"
#include "audit/AuditLog.h"
#include "auth/Permissions.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "http/Middleware.h"
#include "http/JsonIo.h"
#include "http/RateLimitResponse.h"
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

ProfileHandler::ProfileHandler(SqliteStore& store, SyncEngine& sync_engine, const Config& config,
                               LimiterClock clock)
    : store_(store), sync_engine_(sync_engine), config_(config)
    , limits_(config.send_limits, std::move(clock)) {}

bool ProfileHandler::profile_flood(const std::string& user_id, httplib::Response& res) {
    const auto wait = limits_.acquire(SendLimiter::Bucket::kProfile, user_id);
    if (!wait) return false;
    send_rate_limited(res, wait, SendLimiter::message_for(SendLimiter::Bucket::kProfile));
    return true;
}

void ProfileHandler::handle_get_profile(const httplib::Request& req, httplib::Response& res) {

    // AUTHENTICATION. These four GET handlers were the only read endpoints in
    // the server that never called authenticate() — every other one does, which
    // is what marks this as an oversight rather than a decision that profiles
    // are public. Unauthenticated, they hand anyone who can reach the port a
    // user-existence oracle over the whole account namespace (404 vs 200), plus
    // the display name, avatar and per-server nickname of every account found.
    // The rate limiter does not cover this route, so the enumeration is not even
    // slow.
    //
    // The caller is `requester`; `user_id` below is the profile being READ, and
    // conflating the two is how a cross-user write bug gets introduced later.
    // Reading someone else's profile is legitimate — that is what the member
    // list does — so this gates on being signed in, nothing more.
    auto requester = authenticate(store_, req.get_header_value("Authorization"));
    if (!requester) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(),
                        "application/json");
        return;
    }
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

    // json::object(), not a default-constructed json. A default-constructed
    // nlohmann json IS null, and every field below is conditional, so a user with
    // no displayname, no avatar and no nickname dumped the four characters `null`
    // — a 200 whose body is not an object. That breaks the obvious client idioms
    // (`resp.json()["displayname"]`, and even the defensive `.get(key, default)`,
    // both raise), contradicts the spec, which has this endpoint returning an
    // object, and is inconsistent with the rest of the API, which returns `{}`.
    // The same applies to the two single-field getters below.
    json resp = json::object();
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

    res.set_content(dump_response_json(resp), "application/json");
}

void ProfileHandler::handle_get_displayname(const httplib::Request& req, httplib::Response& res) {

    // Signed-in callers only; see handle_get_profile for why these four needed it.
    auto requester = authenticate(store_, req.get_header_value("Authorization"));
    if (!requester) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(),
                        "application/json");
        return;
    }
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

    json resp = json::object();
    auto display_name = store_.get_display_name(user_id);
    if (display_name) resp["displayname"] = *display_name;

    res.set_content(dump_response_json(resp), "application/json");
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
        body = parse_request_json(req.body);
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

    // Size before rate: a refused oversize name must not spend budget either.
    // The name is re-emitted as an m.room.member event into every joined
    // channel (broadcastMemberUpdate), so it is bounded like one field of an
    // event rather than like a request body. See api/InputLimits.h (audit S2).
    const auto displayname = body["displayname"].get<std::string>();
    if (auto err = oversize_field("displayname", displayname,
                                  input_limits::kMaxDisplayNameBytes)) {
        res.status = 400;
        res.set_content(err->to_json().dump(), "application/json");
        return;
    }

    // Charged here, after the request has been validated and immediately before
    // the fan-out it is protecting. Charging earlier would spend budget on
    // malformed requests that were never going to emit anything.
    if (profile_flood(*user_id, res)) return;

    store_.set_display_name(*user_id, displayname);
    broadcastMemberUpdate(*user_id);

    get_logger()->info("User {} updated display name", *user_id);
    res.set_content("{}", "application/json");
}

void ProfileHandler::handle_get_avatar_url(const httplib::Request& req, httplib::Response& res) {

    // Signed-in callers only; see handle_get_profile for why these four needed it.
    auto requester = authenticate(store_, req.get_header_value("Authorization"));
    if (!requester) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(),
                        "application/json");
        return;
    }
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

    json resp = json::object();
    auto avatar_url = store_.get_avatar_url(user_id);
    if (avatar_url) resp["avatar_url"] = *avatar_url;

    res.set_content(dump_response_json(resp), "application/json");
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
        body = parse_request_json(req.body);
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

    const auto avatar_url = body["avatar_url"].get<std::string>();
    if (auto err = oversize_field("avatar_url", avatar_url, input_limits::kMaxAvatarUrlBytes)) {
        res.status = 400;
        res.set_content(err->to_json().dump(), "application/json");
        return;
    }

    if (profile_flood(*user_id, res)) return;

    // The avatar has to be an object THIS account uploaded. Audit F5's worst
    // variant, and the reason the test is "uploaded" and not "can read":
    //
    // MediaAccess rule 3 makes a room-less object readable by every
    // authenticated account when it is somebody's avatar — right, because an
    // avatar is drawn next to its owner's name in every channel and /profile
    // already discloses the URI. Rule 3 is reached only when `media_refs` is
    // EMPTY, and emptying `media_refs` is exactly what a redaction does. So
    // before this check, setting your own avatar_url to a string you copied out
    // of a redacted message promoted that object from channel-scoped to
    // server-public, and a moderator's deletion was the thing that made it
    // possible.
    //
    // "Can read" would not close it. Anyone who can see #general can read what
    // is posted there; if that were the test, they could adopt a colleague's
    // attachment as their avatar and, the moment it was redacted, it would
    // become readable by the whole server. Laundering channel-scoped media into
    // server-public media is the act being refused, so the test has to be
    // ownership, which laundering cannot manufacture.
    //
    // The cost is a real, deliberate narrowing: an avatar must be uploaded with
    // the credential that wears it. A bot's avatar is uploaded with the bot's
    // own token, not handed to it as an id by its operator.
    //
    // An empty string clears the avatar and is always allowed.
    if (!avatar_url.empty()) {
        const std::string prefix = "mxc://" + config_.server_name + "/";
        std::optional<SqliteStore::MediaMeta> meta;
        if (avatar_url.rfind(prefix, 0) == 0) {
            meta = store_.get_media(avatar_url.substr(prefix.size()));
        }
        // ONE refusal for "not on this server", "no such object" and "not
        // yours", byte for byte, for the reason handle_download and
        // handle_ticket answer 404 the same way in both cases: a media id is
        // 128 random bits and this endpoint must not become the oracle that
        // tells someone whether one they guessed or overheard is real.
        if (!meta || meta->uploader != *user_id) {
            res.status = 403;
            res.set_content(MatrixError::forbidden(
                "avatar_url must be an image you uploaded to this server").to_json().dump(),
                "application/json");
            return;
        }
    }

    store_.set_avatar_url(*user_id, avatar_url);
    broadcastMemberUpdate(*user_id);

    get_logger()->info("User {} updated avatar URL", *user_id);
    res.set_content("{}", "application/json");
}

void ProfileHandler::handle_get_nickname(const httplib::Request& req, httplib::Response& res) {

    // Signed-in callers only; see handle_get_profile for why these four needed it.
    auto requester = authenticate(store_, req.get_header_value("Authorization"));
    if (!requester) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(),
                        "application/json");
        return;
    }
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
    res.set_content(dump_response_json(resp), "application/json");
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
        body = parse_request_json(req.body);
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

    // Against the TARGET's budget, not the caller's: the fan-out is over the
    // renamed account's channels, so charging the caller would let one moderator
    // spend a single budget driving a different amplifier on every request.
    if (profile_flood(target_user_id, res)) return;

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
        // Vetted like everything else, which for a member event means vetted
        // against its SUBJECT — here the same account as the sender. The avatar
        // in this content is one handle_put_avatar_url has already established
        // the user uploaded, so this binds it in every room they are in, which
        // is what makes an avatar readable to the people who see it rendered.
        insert_event_vetted(store_, config_, event_id, room_id, user_id,
                            std::string(event_type::kRoomMember),
                            user_id, room_content.dump(), now_ms());
    }
    if (!rooms.empty()) sync_engine_.notify_new_event();
}

} // namespace bsfchat
