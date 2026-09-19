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
#include <algorithm>
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

// Stamps `is_direct` onto an m.room.member content when the room is a DM. See
// the comment at the creator's join in handle_create_room for why the room's
// own state — and not only m.direct account data — has to say so.
json direct_marked(json content, bool is_direct) {
    if (is_direct) content["is_direct"] = true;
    return content;
}

// A DM is a conversation between exactly the two people in it. Everything that
// would change who is in it, or would file it under the server's channel tree,
// is refused on a direct room whatever permissions the caller holds: a role
// that lets someone run the SERVER must not let them run somebody's private
// conversation. Read and send are gated by membership at each handler; this is
// the structural half — nothing can make a DM reachable or listable in the
// first place.
//
// Returns true (and answers the request) when the room is direct.
bool refuse_on_direct_room(SqliteStore& store, httplib::Response& res,
                           const std::string& room_id, const char* what) {
    if (!store.is_direct_room(room_id)) return false;
    res.status = 403;
    res.set_content(MatrixError::forbidden(what).to_json().dump(), "application/json");
    return true;
}

// Membership alone is NOT authorization here: everyone is force-joined into
// every public room, so a user whose VIEW_CHANNEL was explicitly denied for a
// channel was still a joined member and could read its name, topic and full
// member list.
//
// There is NO category exemption here, and there deliberately is one in
// SyncEngine. The exemption exists to let the sidebar draw a container node,
// which /sync serves as a three-event stub (name, type, ordering). These three
// endpoints — GET /rooms/{id}/state, /state/{type} and /members — answer with
// the room's WHOLE state and its complete member list, which is not a sidebar
// requirement and is not something a stub can express. The client never calls
// them for a node it cannot open, so they simply refuse. Reinstating the
// exemption here would hand back everything /sync stopped disclosing.
bool can_read_room(SqliteStore& store, const Config& config,
                   const std::string& user_id, const std::string& room_id) {
    if (!store.is_room_member(room_id, user_id)) return false;
    PermissionsEngine perms(store, config);
    return perms.can(user_id, room_id, permission::kViewChannel);
}

// What a membership transition IS, and therefore what gates it.
//
// Derived from the (before, after) pair and the ban list — NOT from which URL the
// request arrived at. That is the whole point: POST /rooms/{id}/ban and
// PUT /rooms/{id}/state/m.room.member/{user} describe the same act, so they must
// not be able to disagree about which permission it needs, whether rank applies,
// or what it writes.
struct MembershipIntent {
    bool recognised = false;
    permission::Flags required = 0;
    bool server_scope = false;       // where `required` is evaluated
    bool needs_rank = false;         // acting against the target, so rank applies
    bool places_server_ban = false;
    bool lifts_server_ban = false;
    bool require_target_in_room = false;
    bool require_target_banned = false;
    const char* verb = "";           // "ban"/"unban"/"kick"/"invite", for messages
};

MembershipIntent ban_intent() {
    // BAN_MEMBERS, not KICK_MEMBERS. The generic state route used to gate every
    // member write on KICK_MEMBERS, so a kick-only moderator could ban there after
    // being refused at POST /rooms/{id}/ban.
    MembershipIntent i;
    i.recognised = true;
    i.required = permission::kBanMembers;
    i.server_scope = true;
    i.needs_rank = true;
    i.places_server_ban = true;
    i.verb = "ban";
    return i;
}

MembershipIntent unban_intent() {
    // Lifting a ban needs the permission that imposed it, per the Matrix spec and
    // per the endpoint this replaces.
    MembershipIntent i;
    i.recognised = true;
    i.required = permission::kBanMembers;
    i.server_scope = true;
    i.needs_rank = true;
    i.lifts_server_ban = true;
    i.require_target_banned = true;
    i.verb = "unban";
    return i;
}

MembershipIntent kick_intent() {
    MembershipIntent i;
    i.recognised = true;
    i.required = permission::kKickMembers;
    i.server_scope = true;
    i.needs_rank = true;
    i.require_target_in_room = true;
    i.verb = "kick";
    return i;
}

MembershipIntent invite_intent() {
    // Matches the dedicated invite endpoint: there is no separate invite flag, and
    // pulling somebody into one channel is a per-channel act, so it stays
    // channel-scoped. Deliberately NO rank check — you must be able to invite an
    // admin to a channel.
    MembershipIntent i;
    i.recognised = true;
    i.required = permission::kManageChannels;
    i.verb = "invite";
    return i;
}

MembershipIntent classify_transition(MembershipAction declared, const std::string& after,
                                     const std::string& before, bool target_server_banned) {
    switch (declared) {
        case MembershipAction::kKick: return kick_intent();
        case MembershipAction::kBan: return ban_intent();
        case MembershipAction::kUnban: return unban_intent();
        case MembershipAction::kInvite: return invite_intent();
        case MembershipAction::kInfer: break;
    }

    // Only the generic state route infers, because it is the only caller that
    // does not know what it is doing: the client sends a target membership and the
    // meaning comes from where the target currently stands. A dedicated endpoint
    // must NOT infer — POST /rooms/{id}/kick against an already-banned user would
    // otherwise be read as "leave a banned user" and quietly LIFT the ban.
    if (after == membership::kBan) return ban_intent();
    if (after == membership::kLeave) {
        if (before == membership::kBan || target_server_banned) {
            // A Matrix client lifts a ban exactly this way, so the state route has
            // to honour it — and honour it as an unban, at BAN_MEMBERS.
            auto i = unban_intent();
            i.require_target_banned = false;  // already established
            return i;
        }
        auto i = kick_intent();
        // The state route has always tolerated writing "leave" for a user who is
        // not currently joined; keeping that avoids turning a harmless no-op write
        // by a Matrix client into a 403.
        i.require_target_in_room = false;
        return i;
    }
    if (after == membership::kInvite || after == membership::kJoin) return invite_intent();
    return {};
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

std::string RoomHandler::project_membership_everywhere(const std::string& actor,
                                                       const std::string& origin_room,
                                                       const std::string& target_user,
                                                       const std::string& membership_value,
                                                       const std::string& reason,
                                                       const std::string& only_when) {
    json content = {{"membership", membership_value}};
    if (!reason.empty()) content["reason"] = reason;

    // get_user_memberships is a single indexed query over room_members, so this
    // reaches EVERY channel the user has a row in — including the ones the
    // moderator's client had never synced, which is precisely the set the client's
    // loop silently skipped.
    std::vector<std::string> rooms;
    for (const auto& [room_id, current] : store_.get_user_memberships(target_user)) {
        if (!only_when.empty() && current != only_when) continue;
        if (current == membership_value) continue;  // already there; no event spam
        rooms.push_back(room_id);
    }

    // A ban rewrites every row (only_when empty), so the room the request named
    // must be written even when the target has no row in it at all — POST
    // /rooms/{id}/ban on a non-member must still produce a ban there, and the
    // audit record names this room. An unban is filtered (only_when = "ban") and
    // gets no such override on purpose: forcing "leave" into the origin room would
    // eject a user from a channel they were still joined to.
    if (only_when.empty() && !origin_room.empty() &&
        store_.get_membership(origin_room, target_user) != membership_value) {
        if (std::find(rooms.begin(), rooms.end(), origin_room) == rooms.end()) {
            rooms.push_back(origin_room);
        }
    }

    std::string origin_event_id;
    for (const auto& room_id : rooms) {
        store_.set_membership(room_id, target_user, membership_value);
        auto event_id = emit_state_event(room_id, actor, std::string(event_type::kRoomMember),
                                        target_user, content);
        if (room_id == origin_room) origin_event_id = event_id;
    }
    return origin_event_id;
}

RoomHandler::ModerationResult RoomHandler::apply_membership_moderation(
    const std::string& actor, const std::string& room_id, const std::string& target_user,
    const std::string& target_membership, const std::string& reason,
    MembershipAction declared) {
    ModerationResult refusal;
    if (target_user.empty()) {
        refusal.status = 400;
        refusal.message = "Missing user_id";
        return refusal;
    }

    const std::string before = store_.get_membership(room_id, target_user);
    const bool target_banned = store_.is_server_banned(target_user);

    const auto intent = classify_transition(declared, target_membership, before, target_banned);
    if (!intent.recognised) {
        refusal.message = "Unsupported membership: " + target_membership;
        return refusal;
    }

    PermissionsEngine perms(store_, config_);
    // SERVER scope (empty room_id) for kick/ban/unban: these are server-wide
    // capabilities, as in Discord — there is no per-channel kick and no UI to
    // grant one, so a per-channel override must not confer them. See
    // PermissionsEngine::compute: an empty room_id returns before any channel
    // override is applied.
    const std::string scope = intent.server_scope ? kServerScope : room_id;
    if (!perms.can(actor, scope, intent.required)) {
        refusal.message = std::string("Insufficient permissions to ") + intent.verb;
        return refusal;
    }
    if (intent.needs_rank && !perms.outranks(actor, target_user)) {
        refusal.message =
            std::string("Cannot ") + intent.verb + " a user with equal or higher role";
        return refusal;
    }
    // These are ordered AFTER the permission and rank checks so an unauthorised
    // caller learns nothing about the target's state from the refusal it gets.
    if (intent.require_target_in_room && before != membership::kJoin &&
        before != membership::kInvite) {
        refusal.message = "User is not in the room";
        return refusal;
    }
    if (intent.require_target_banned && before != membership::kBan && !target_banned) {
        refusal.message = "User is not banned";
        return refusal;
    }
    // An invite is not a way around a ban. This is one of the entry points a
    // client-side ban loop could never protect.
    if (target_banned && !intent.lifts_server_ban && !intent.places_server_ban) {
        refusal.message = "User is banned from this server";
        return refusal;
    }

    ModerationResult ok;
    ok.ok = true;
    ok.status = 200;

    if (intent.places_server_ban) {
        // The ban list first, then the sessions, then the projection. Both
        // orderings are load-bearing.
        //
        // Ban row before revocation: revoking first would leave a window in which
        // the target holds no token, is not yet banned, and can simply log in
        // again — handing them a fresh 90-day session created moments before the
        // ban lands. Writing the ban first means anything they re-authenticate
        // into is already refused.
        //
        // Ban row before projection: the list is the authoritative record and the
        // membership rows are its projection, so a crash between them leaves a ban
        // that /join, auto-join and /sync all still enforce — fail-closed — rather
        // than membership rows nobody can explain.
        store_.set_server_ban(target_user, actor, reason, now_ms());

        // Revoke every session. Reuses the /logout/all primitive rather than
        // adding a second revocation path: refresh tokens are a column on the
        // access-token row, so this is the only operation that cannot leave one of
        // the pair alive. A ban is not "you may stay signed in but see nothing" —
        // and without this, enforcement depended on every future read path
        // remembering to consult the ban list.
        //
        // Revoking zero sessions is an ordinary outcome (an account that never
        // logged in, or is already logged out), not an error.
        const int revoked = store_.delete_all_tokens_for_user(target_user);

        ok.event_id = project_membership_everywhere(actor, room_id, target_user,
                                                    std::string(membership::kBan), reason, "");
        get_logger()->info("Server ban on {} by {} revoked {} session(s)", target_user, actor,
                           revoked);
    } else if (intent.lifts_server_ban) {
        store_.clear_server_ban(target_user);
        // "leave", not "join": lifting a ban restores the user's ability to come
        // back, it does not decide for them that they have.
        ok.event_id = project_membership_everywhere(actor, room_id, target_user,
                                                    std::string(membership::kLeave), reason,
                                                    std::string(membership::kBan));
    } else {
        // A kick or an invite is genuinely per-channel and touches one room.
        //
        // THE MEMBERSHIP ROW AND THE EVENT ARE WRITTEN TOGETHER, ALWAYS. The
        // generic state route used to emit only the event, so a ban placed there
        // left room_members saying "join": clients hid the user while every
        // server-side check (sync, room reads, search, push, and the membership
        // guard on the route itself) still treated them as a joined member.
        store_.set_membership(room_id, target_user, target_membership);
        json content = {{"membership", target_membership}};
        if (!reason.empty()) content["reason"] = reason;
        ok.event_id = emit_state_event(room_id, actor, std::string(event_type::kRoomMember),
                                       target_user, content);
    }

    // ONE record per moderator decision, naming the room the request arrived
    // through. Deliberately not one per projected room: a server ban is a single
    // act of authority, and a 40-channel server would otherwise bury the log under
    // 40 rows describing the mechanical consequence of one click.
    audit_membership_change(store_, actor, room_id, target_user, before, target_membership,
                            reason);

    return ok;
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

    // One DM per pair. A client can only de-duplicate against what it has
    // already synced, which loses to a second device, to a double click that
    // beats the first reply, and to both people opening the DM at the same
    // moment. The store is the one place that sees all of those, so an
    // existing direct room with the same single peer is handed back instead of
    // minting a twin. Both sides must still be joined: returning a room the
    // caller has left would drop them into a conversation they cannot read.
    if (is_direct && room_req.invite.size() == 1 && room_req.invite.front() != *user_id) {
        if (auto existing = store_.find_direct_room(*user_id, room_req.invite.front())) {
            CreateRoomResponse existing_resp;
            existing_resp.room_id = *existing;
            json existing_json;
            to_json(existing_json, existing_resp);
            res.set_content(existing_json.dump(), "application/json");
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
    //
    // `is_direct` on the membership content is the Matrix marker, and it is
    // written for BOTH sides (see the invite loop below). m.direct in /sync
    // already tells each participant which of their rooms are DMs, but it is
    // account data: a client that has never seen the one sync response
    // carrying it — a fresh profile, a reset settings file, a sync that
    // errored at the wrong moment — has nothing in the room itself to
    // classify it by, and files the DM under channels. The marker rides along
    // in the room's own state, which every client gets on every initial sync
    // and can never be out of step with the room.
    store_.set_membership(room_id, *user_id, std::string(membership::kJoin));
    emit_state_event(room_id, *user_id, std::string(event_type::kRoomMember), *user_id,
                     direct_marked(member_event_content(
                         store_, *user_id, std::string(membership::kJoin)), is_direct));

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
        // Creating a room with a banned user in `invite` is otherwise a way to
        // hand them a fresh channel: the room is new, so there is no membership
        // row for the ban projection to have touched.
        if (store_.is_server_banned(invitee)) continue;

        const auto state = is_direct ? membership::kJoin : membership::kInvite;
        store_.set_membership(room_id, invitee, std::string(state));

        // member_event_content fills profile fields for join AND invite; the
        // previous code filled them only for the direct-room join, so a plain
        // invite carried no name. Both now carry the effective name, which is what
        // the invitee's nickname makes it.
        emit_state_event(room_id, *user_id, std::string(event_type::kRoomMember), invitee,
                         direct_marked(member_event_content(store_, invitee, std::string(state)),
                                       is_direct));
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

    // A server-wide ban is checked BEFORE the room is even looked up, so a banned
    // user cannot use this endpoint to probe which room ids exist. This is the
    // check that makes a ban mean something: the projection across room_members
    // stops them being a member of today's channels, and this stops them walking
    // back into any of them — or into a channel created after the ban, which has
    // no membership row to project onto.
    if (store_.is_server_banned(*user_id)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("You are banned from this server").to_json().dump(),
                        "application/json");
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

    // A DM is not server structure, so MANAGE_CHANNELS does not reach it. This
    // endpoint has no membership check at all — deliberately, because deleting
    // a channel is a moderator act performed from outside it — which meant a
    // role that runs the server could destroy any two people's conversation,
    // and audit_room_deletion below would record its member list on the way
    // out. Participants only.
    if (store_.is_direct_room(room_id) && !store_.is_room_member(room_id, *user_id)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden(
            "Not a participant in this direct message").to_json().dump(), "application/json");
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

    // Permission scope, rank, the membership row, the event and the audit record
    // all live in apply_membership_moderation — see its declaration for why this
    // endpoint no longer carries its own copy of any of them.
    auto outcome = apply_membership_moderation(*user_id, room_id, target_user,
                                              std::string(membership::kLeave), reason,
                                              MembershipAction::kKick);
    if (!outcome.ok) {
        res.status = outcome.status;
        res.set_content((outcome.status == 400 ? MatrixError::bad_json(outcome.message)
                                              : MatrixError::forbidden(outcome.message))
                            .to_json().dump(),
                        "application/json");
        return;
    }

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

    // A ban is SERVER-WIDE, and this endpoint is where it is placed.
    //
    // It was already server-wide in intent — the client implemented "ban from
    // server" by looping this endpoint over every room its sync had surfaced, and
    // the permission has been evaluated at server scope since that intent was
    // recognised. What was missing was anywhere for the ban to LIVE, so channels
    // the moderator's client had not synced kept the user and auto-join could put
    // them back. apply_membership_moderation now writes the ban list and projects
    // it across every room in one server-side act; `room_id` survives only as the
    // context recorded in the audit trail.
    auto outcome = apply_membership_moderation(*user_id, room_id, target_user,
                                              std::string(membership::kBan), reason,
                                              MembershipAction::kBan);
    if (!outcome.ok) {
        res.status = outcome.status;
        res.set_content((outcome.status == 400 ? MatrixError::bad_json(outcome.message)
                                              : MatrixError::forbidden(outcome.message))
                            .to_json().dump(),
                        "application/json");
        return;
    }

    res.set_content("{}", "application/json");
    get_logger()->info("User {} banned {} from the server (requested via room {})", *user_id,
                       target_user, room_id);
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

    // Interoperates with the server-wide ban by BEING the server-wide unban: it
    // clears the ban-list row and restores every room where the projection had set
    // "ban" back to "leave". The client's per-room unban loop therefore still
    // works — the first call lifts the ban and the rest are idempotent no-ops —
    // and it is no longer the only thing standing between a banned user and a
    // channel the loop forgot.
    //
    // A row in room_members that says "ban" with no ban-list entry (a legacy
    // per-room ban, or one recovered by migrate_v15 and since cleared) is still
    // liftable: the precondition is "banned here OR banned server-wide".
    auto outcome = apply_membership_moderation(*user_id, room_id, target_user,
                                              std::string(membership::kLeave), reason,
                                              MembershipAction::kUnban);
    if (!outcome.ok) {
        res.status = outcome.status;
        res.set_content((outcome.status == 400 ? MatrixError::bad_json(outcome.message)
                                              : MatrixError::forbidden(outcome.message))
                            .to_json().dump(),
                        "application/json");
        return;
    }

    res.set_content("{}", "application/json");
    get_logger()->info("User {} unbanned {} (requested via room {})", *user_id, target_user,
                       room_id);
}

void RoomHandler::handle_list_server_bans(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(),
                        "application/json");
        return;
    }

    const auto refuse = [&](int status, const MatrixError& err) {
        res.status = status;
        res.set_content(err.to_json().dump(), "application/json");
    };

    // SERVER scope. kServerScope is the empty room id, and PermissionsEngine::
    // compute returns before any channel override is applied for it — so a
    // per-channel BAN_MEMBERS override cannot unlock the server-wide ban list.
    // That escalation shape has been a real bug here twice (the role-write path
    // and, nearly, the audit log), and this endpoint is exactly the sort of
    // server-wide read that invites it. ADMINISTRATOR still passes: compute()
    // short-circuits it from the ROLE base before overrides are considered.
    //
    // BAN_MEMBERS rather than MANAGE_SERVER, matching ban_intent()/unban_intent()
    // above: the permission that places and lifts a ban is the permission that
    // sees them. See the note in RoomHandler.h.
    PermissionsEngine perms(store_, config_);
    if (!perms.can(*user_id, kServerScope, permission::kBanMembers)) {
        return refuse(403, MatrixError::forbidden(
            "Insufficient permissions to read the server ban list"));
    }

    int limit = limits::kDefaultServerBanLimit;
    if (req.has_param("limit")) {
        try {
            limit = std::clamp(std::stoi(req.get_param_value("limit")), 1,
                               limits::kMaxServerBanLimit);
        } catch (const std::exception&) {
            return refuse(400, MatrixError::invalid_param("limit must be an integer"));
        }
    }

    std::optional<std::string> after;
    if (req.has_param("after")) {
        // Rejected rather than silently ignored, for the same reason the audit
        // log's cursor is: a cursor treated as "start from the beginning" hands a
        // paginating caller page one forever while looking like progress, and a
        // moderator would conclude the ban list ends where it does not.
        auto value = req.get_param_value("after");
        if (value.empty()) {
            return refuse(400, MatrixError::invalid_param("after must not be empty"));
        }
        after = std::move(value);
    }

    auto page = store_.list_server_bans(limit, after);

    json bans = json::array();
    for (const auto& ban : page.bans) {
        json entry = {{"user_id", ban.user_id}, {"created_at", ban.created_at}};
        // Omitted rather than emitted as "": migrate_v15 recovered pre-existing
        // per-room bans that the database never recorded an actor for, and an
        // empty string there would render as a moderator with no name rather than
        // as "unknown". Same for a ban placed without a reason.
        if (!ban.actor.empty()) entry["actor"] = ban.actor;
        if (!ban.reason.empty()) entry["reason"] = ban.reason;
        // The name a moderator recognises. Included because the client cannot
        // work it out for exactly the users this endpoint exists to surface: it
        // reads display names out of the m.room.member events its sync delivered,
        // and a user banned while holding no membership row anywhere has none — so
        // without this they would appear in the bans tab as a bare MXID.
        //
        // Via effective_display_name so nickname-over-profile precedence is the
        // one definition every member event already uses, rather than a second
        // rule invented here. Absent when the account row is gone: a ban
        // deliberately outlives the account it names (see migrate_v15), so this
        // being missing is normal and means "no name on record", not an error.
        //
        // Cost: two primary-key lookups on `users` per row, so up to 1000 for a
        // full 500-row page. That is an N+1 and could be a LEFT JOIN, but this is
        // an admin-only read a moderator opens occasionally, and reusing the one
        // authoritative helper is worth more here than collapsing the query.
        if (auto name = effective_display_name(store_, ban.user_id)) {
            entry["display_name"] = *name;
        }
        bans.push_back(std::move(entry));
    }

    json out = {
        {"bans", std::move(bans)},
        {"total", page.total},
    };
    if (page.next_from) out["next_from"] = *page.next_from;
    res.set_content(out.dump(), "application/json");
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
    // Even a participant cannot widen a DM: "only the two of us" is the whole
    // guarantee, and a third member would also be handed the entire backlog.
    if (refuse_on_direct_room(store_, res, room_id,
                              "Cannot invite someone into a direct message")) {
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
    // The per-room check above is not enough on its own: a channel created AFTER
    // the ban has no membership row for the banned user, so get_membership returns
    // "leave" and the invite would go through. The ban list is the thing that
    // knows, and it is the only thing that keeps working as channels come and go.
    if (store_.is_server_banned(target_user)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("User is banned from this server").to_json().dump(),
                        "application/json");
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

    // The generic state route is the back door to the dedicated ones, so the
    // DM guards on /category and /order have to hold here too — otherwise a
    // participant with MANAGE_CHANNELS re-files their DM into a category, or
    // reopens its join rules, by writing the state event directly.
    if ((evt_type == std::string(event_type::kRoomCategory) ||
         evt_type == std::string(event_type::kRoomType) ||
         evt_type == std::string(event_type::kRoomJoinRules)) &&
        refuse_on_direct_room(store_, res, room_id,
                              "A direct message is not a channel and its structure cannot be changed")) {
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

    // Changing an existing room's KIND is an act on the server's channel tree,
    // not an edit inside one channel, and it is the lever that made the
    // category exemption a privilege escalation: at room scope, an allow
    // override on a single channel — the natural way to give someone their own
    // channel — was enough to retype any channel as a category and inherit the
    // exemption. `may_edit_role_definitions` already states the principle for
    // MANAGE_ROLES ("must not be a one-request path to owning the server"); it
    // is the same sentence about MANAGE_CHANNELS and reading every channel.
    //
    // Only the permission SCOPE moves. Unlike the two types above, the event
    // still belongs to the room and is still written as ordinary room state,
    // which is why this is a separate flag and not folded into
    // `is_server_scoped`. Room CREATION is unaffected: handle_create_room
    // writes the initial type itself, behind its own server-scope
    // MANAGE_CHANNELS check, on a room that is empty by construction.
    const bool is_room_type_change = evt_type == std::string(event_type::kRoomType);

    // Moderation-by-membership-write. This route will happily set another user's
    // m.room.member to "ban", which makes it a second route to the same act as
    // POST /rooms/{id}/ban — and Matrix clients legitimately use it, so it cannot
    // simply be refused. It is therefore no longer implemented here AT ALL: it
    // delegates to apply_membership_moderation below, which is the same code the
    // dedicated endpoints run.
    //
    // Reimplementing it here is what produced every defect this route has had. It
    // gated a ban on KICK_MEMBERS while /ban required BAN_MEMBERS; it evaluated at
    // channel scope after the dedicated endpoints had moved to server scope; it
    // lacked their rank check; and it wrote the m.room.member EVENT while never
    // calling set_membership, so a ban placed here left room_members saying "join"
    // — clients hid the user while sync, room reads, search, push and the
    // permission engine all still saw a joined member. Four divergences in one
    // duplicated code path.
    //
    // Self-membership is excluded: it is handled below and is a genuinely
    // per-channel action (joining and leaving a channel).
    const bool is_member_moderation =
        evt_type == std::string(event_type::kRoomMember) && state_key != *user_id;

    // Map the state event type to the permission flag that gates it.
    permission::Flags required = permission::kManageChannels;
    if (is_server_scoped || evt_type == std::string(event_type::kChannelPermissions)) {
        required = permission::kManageRoles;
    } else if (evt_type == std::string(event_type::kServerInfo)) {
        required = permission::kManageServer;
    }

    PermissionsEngine perms(store_, config_);
    // `is_server_scoped` also decides WHERE the write lands (server_state vs room
    // state), which is why it is not folded into the scope expression below.
    const std::string perm_scope =
        (is_server_scoped || is_room_type_change) ? kServerScope : room_id;

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

    // Moderating another user's membership: hand the whole decision to the shared
    // implementation and return. Permission scope, the rank check, the ban list,
    // the membership row, the member event and the audit record are all its job —
    // this route contributes nothing of its own, which is the only arrangement in
    // which it cannot drift from the dedicated endpoints again.
    //
    // The empty-state_key guard matters: this route also matches
    // /state/m.room.member with no state key at all, which names no target.
    if (is_member_moderation) {
        if (state_key.empty()) {
            res.status = 400;
            res.set_content(MatrixError::bad_json("Missing user id in state key").to_json().dump(),
                            "application/json");
            return;
        }
        auto outcome = apply_membership_moderation(*user_id, room_id, state_key,
                                                  content.value("membership", ""),
                                                  content.value("reason", ""),
                                                  MembershipAction::kInfer);
        if (!outcome.ok) {
            res.status = outcome.status;
            res.set_content((outcome.status == 400 ? MatrixError::bad_json(outcome.message)
                                                  : MatrixError::forbidden(outcome.message))
                                .to_json().dump(),
                            "application/json");
            return;
        }
        res.set_content(json{{"event_id", outcome.event_id}}.dump(), "application/json");
        return;
    }

    if (!perms.can(*user_id, perm_scope, required)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Insufficient permissions for this state event").to_json().dump(), "application/json");
        return;
    }

    // ── bsfchat.room.type: the conversion gate ────────────────────────────
    //
    // Retyping an existing channel as a category used to be a silent,
    // reversible, one-request publication of that channel: membership rows
    // survive the change (everyone is force-joined into every channel), so the
    // room simply reappeared in every user's /sync with the exemption applied.
    // Narrowing the exemption — see SyncEngine's room_view() — bounds the
    // damage to a name and a sort order. This bounds the act itself.
    //
    // Three rules, deliberately overlapping, because each fails differently:
    // the scope check above stops a per-channel grant being a server-wide
    // lever, the refusals below stop the conversion being a disclosure at all,
    // and the audit record below stops it being silent even when it is allowed.
    std::string previous_room_type;
    if (is_room_type_change) {
        auto existing = store_.get_state_event(room_id, evt_type, state_key);
        previous_room_type = existing ? existing->content.data.value("type", "") : "";
        const std::string new_room_type = content.value("type", "");

        // You may not restructure a channel you are not allowed to open. A
        // server-wide MANAGE_CHANNELS holder is a builder, not an
        // administrator, and a channel that denies them VIEW_CHANNEL is a
        // channel they have been told is not theirs. (Administrators
        // short-circuit every flag, as everywhere.)
        if (!perms.can(*user_id, room_id, permission::kViewChannel)) {
            res.status = 403;
            res.set_content(MatrixError::forbidden(
                "No access to this channel").to_json().dump(), "application/json");
            return;
        }

        if (new_room_type == "category" && previous_room_type != "category") {
            // A category is a container, so an empty room can become one
            // freely. A room with a conversation in it is a channel, and
            // turning a channel into a container is not a reorganisation —
            // it is a decision about who may read that conversation, taken
            // through a request that says nothing about reading. The operator
            // who genuinely wants this deletes the channel or moves the
            // messages; there is no honest one-click version.
            if (store_.room_has_messages(room_id)) {
                res.status = 403;
                res.set_content(MatrixError::forbidden(
                    "A channel with message history cannot be converted into a category")
                        .to_json().dump(), "application/json");
                return;
            }
            // And the override case, which is the one the audits actually
            // exploited: a room that denies VIEW_CHANNEL to anyone is a room
            // whose visibility somebody configured on purpose. Converting it
            // would hand that decision to a rule about sidebars. Refuse even
            // when the room is empty — the override outlives the emptiness.
            for (const auto& ev : store_.get_state_events(room_id)) {
                if (ev.type != event_type::kChannelPermissions) continue;
                ChannelPermissionOverride override;
                try {
                    from_json(ev.content.data, override);
                } catch (const std::exception&) {
                    continue;
                }
                if (!permission::has(override.deny, permission::kViewChannel)) continue;
                res.status = 403;
                res.set_content(MatrixError::forbidden(
                    "A channel with a VIEW_CHANNEL restriction cannot be converted into a "
                    "category").to_json().dump(), "application/json");
                return;
            }
        }
    }

    if (is_server_scoped) {
        // MANAGE_ROLES says you may edit roles; it does not say WHICH. Without
        // a rank check on this path, one request — PUT .../bsfchat.member.roles/
        // @self with {"role_ids":["admin"]} — turned the "builder" role an owner
        // hands to a trusted non-admin into full ADMINISTRATOR. Rewriting
        // bsfchat.server.roles to put ADMINISTRATOR on @everyone was the same
        // trick from the other side. Administrators are exempt, as everywhere.
        PermissionsEngine::RoleChangeVerdict verdict;
        if (evt_type == std::string(event_type::kMemberRoles)) {
            if (state_key.empty()) {
                res.status = 400;
                res.set_content(MatrixError::bad_json("Missing user id in state key")
                                    .to_json().dump(), "application/json");
                return;
            }
            MemberRolesContent assignment;
            try {
                from_json(content, assignment);
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(MatrixError::bad_json("Malformed role assignment")
                                    .to_json().dump(), "application/json");
                return;
            }
            verdict = perms.may_assign_roles(*user_id, state_key, assignment.role_ids);
        } else {
            ServerRolesContent definitions;
            try {
                from_json(content, definitions);
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(MatrixError::bad_json("Malformed role list")
                                    .to_json().dump(), "application/json");
                return;
            }
            verdict = perms.may_edit_role_definitions(*user_id, definitions.roles);
        }
        if (!verdict.allowed) {
            res.status = 403;
            res.set_content(MatrixError::forbidden(verdict.reason).to_json().dump(),
                            "application/json");
            return;
        }

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

    // No m.room.member case here any more: self-membership returned above and
    // moderation of another user returned at the delegation block. The audit write
    // for a membership change lives in apply_membership_moderation, which is the
    // single place every route that can produce one now passes through.
    std::optional<std::string> previous_state;
    if (is_channel_override) {
        auto existing = store_.get_state_event(room_id, evt_type, state_key);
        if (existing) previous_state = existing->content.data.dump();
    }

    // Echo back the id that was actually stored — this used to generate a
    // second, unrelated id and hand the client an event_id not in the database.
    auto event_id = emit_state_event(room_id, *user_id, evt_type, state_key, content);

    if (is_channel_override) {
        audit_channel_override_change(store_, *user_id, room_id, state_key, previous_state,
                                      content.dump());
    }
    if (is_room_type_change) {
        // Recorded in BOTH directions. Category → channel is the tightening
        // half, but it is also the second step of the attack the audits
        // described: convert, read the sync, convert back. A record of only
        // the outbound leg would leave the log showing a channel that had
        // always been a channel.
        audit_room_type_change(store_, *user_id, room_id, previous_room_type,
                               content.value("type", ""));
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
    // A DM has no place in the server's channel tree, so it cannot be given a
    // parent category — which is exactly what would make it render as one.
    if (refuse_on_direct_room(store_, res, room_id,
                              "A direct message is not a channel and cannot be categorised")) {
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

    // Validate parent is a category type. Through the shared predicate, so the
    // one definition of "is a category" governs both this and the conversion
    // gate in handle_set_state — a second hand-rolled copy of the same test is
    // how the two would drift.
    if (!is_category_room(store_, parent_id)) {
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

    if (refuse_on_direct_room(store_, res, room_id,
                              "A direct message is not a channel and cannot be reordered")) {
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
