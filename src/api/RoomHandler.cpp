#include "api/RoomHandler.h"
#include "audit/AuditLog.h"
#include "auth/AutoJoin.h"
#include "auth/Permissions.h"
#include "auth/RoleBootstrap.h"
#include "auth/RoomVisibility.h"
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
// MEMBERSHIP IS THE OTHER HALF AND IT IS NOT DONE HERE. "Who is in it" is
// decided by MembershipIntent::direct_room_refusal, one field on the intent
// every membership write is classified into, because there are two doors to
// that write and only one of them called this helper — see that field.
//
// Returns true (and answers the request) when the room is direct.
// `reason` is the refusal::k* code to put in `bsfchat.errcode`, and is empty
// for the three call sites that have no client keying on them yet. Empty means
// the body is byte-identical to what it has always been, so leaving it off is
// not a regression — it is the status quo, and the field can be filled in when
// something needs it.
bool refuse_on_direct_room(SqliteStore& store, httplib::Response& res,
                           const std::string& room_id, const char* what,
                           std::string_view reason = {}) {
    if (!store.is_direct_room(room_id)) return false;
    res.status = 403;
    res.set_content(MatrixError::forbidden(what, reason).to_json().dump(), "application/json");
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
    // NOT can_view_room(): that one is the LISTING rule and deliberately exempts
    // categories so the sidebar can render a container whose children are all
    // hidden. This is the READING rule, and the comment above spells out why the
    // two must differ — /state, /state/{type} and /members answer with whole
    // state and whole member lists, which a category stub cannot express and
    // which the exemption would hand back wholesale.
    //
    // Merging the joined-rooms-leak and category-visibility branches wired this
    // to can_view_room and silently restored the bypass; CategoryVisibility
    // .StateAndMembersRefuseOnAHiddenCategory is what caught it. Keep them apart.
    return perms.can(user_id, room_id, permission::kViewChannel);
}

// What a membership transition IS, and therefore what gates it.
//
// Marks an m.room.member `leave` that a MODERATOR wrote as a removal, carrying
// the actor's id. Room state, not a new table, so it needs no migration and it
// travels with the event that already describes the act.
//
// WHY THE SENDER IS NOT ENOUGH, which is the entire reason this key exists.
// "the member event says leave and somebody else sent it" looks like a complete
// definition of a kick. It is not: unban_intent projects
// `{"membership":"leave"}` with the MODERATOR as sender into every room where
// the target's row was `ban` (see project_membership_everywhere), precisely so
// that lifting a ban restores the ability to come back — its own comment says
// it "does not decide for them that they have". By sender alone that event is a
// kick in every channel at once, so a sender-only rule would leave every
// unbanned account permanently locked out of the entire server. This key is
// written by exactly one intent, so the two acts cannot be confused.
//
// ON THE KICK RATHER THAN ON THE UNBAN, deliberately. Neither marker exists on
// rows written before this change. Marking the kick means those historical
// kicks stay rejoinable, which is today's behaviour and therefore no
// regression; marking the unban instead would silently re-lock everybody
// unbanned before the upgrade, which is a new lockout nobody asked for. When
// the evidence is missing, fail open: this is a moderation control, not a
// confidentiality boundary — a kicked user could already read the channel
// (finding 6: "This is not disclosure") — so wrongly refusing a legitimate
// member is the worse error.
//
// Server-local, not a protocol constant: no client has to understand it, and an
// unknown key in a member event is ignored. It disappears on its own, because
// every later membership write REPLACES the state event — an invite writes a
// fresh content object, and so does a join — so re-admitting somebody clears it
// without anything having to remember to.
constexpr std::string_view kRemovedByKey = "bsfchat.removed_by";

// True when `user_id`'s CURRENT membership in `room_id` is a removal somebody
// else performed. Both halves are required: the marker says which act it was,
// and the sender check keeps a self-write from ever counting however the
// content was built.
bool was_removed_by_moderator(SqliteStore& store, const std::string& room_id,
                              const std::string& user_id) {
    auto ev = store.get_state_event(room_id, std::string(event_type::kRoomMember), user_id);
    if (!ev) return false;
    if (ev->sender == user_id) return false;
    if (!ev->content.data.is_object()) return false;
    if (ev->content.data.value("membership", "") != membership::kLeave) return false;
    return ev->content.data.contains(std::string(kRemovedByKey));
}

// ONE wording for every way an invited id can fail to name an account: a
// mistyped localpart, an id on somebody else's homeserver, a string that is not
// an mxid at all. Shared by POST /rooms/{id}/invite and the generic state route
// so the two cannot drift into two sentences for one fact.
//
// ── Why the server says this at all ──────────────────────────────────────
//
// It did not, and that was the bug: handle_invite never called user_exists()
// and room_members has no foreign key to `users`, so inviting @tpyo:chat.
// bsfchat.com answered 200 and wrote a membership row for nobody. The invitee
// never appeared, the inviter had no way to find out, and the row stayed —
// in the roster, in joined-member counts, in the presence sweep, and in every
// later projection that walks room_members.
//
// ── Why it is not an account-existence oracle ────────────────────────────
//
// "Does this account exist" is the question a directory attack asks, so this
// refusal has to justify answering it. Three reasons it is safe here, and the
// first is the one that matters:
//
//   * It discloses nothing a caller cannot already get more cheaply. GET
//     /profile/{userId} answers 404 for an unknown account and 200 for a known
//     one, to ANY authenticated caller, and says so in as many words
//     (ProfileHandler.cpp). This refusal needs MANAGE_CHANNELS in a room the
//     caller is already in, and costs a write-path request per guess. It is a
//     strictly smaller oracle than the one already on the server — which is
//     also the standing condition on this decision: if /profile is ever closed,
//     this must be closed with it, or it becomes the new way to walk the
//     namespace.
//
//   * The endpoint already discloses more than this about a named target, on
//     purpose. It distinguishes "banned from this room" from "banned from this
//     server" from "deactivated bot", because a moderator who cannot tell why
//     an invite failed cannot fix it. Existence is the least sensitive fact in
//     that set.
//
//   * It is ordered AFTER the MANAGE_CHANNELS check (and, on the state route,
//     after the rank check), so an ordinary member gets byte-identical answers
//     for a real id and a fictional one. That ordering is the actual boundary
//     and it is pinned by a test.
//
// This deliberately DIFFERS from PermissionsHandler's kRefusal, which answers
// "stranger", "invisible member" and "no such account" identically. That is a
// read endpoint: its refusal is its only output, and no caller has a use for
// the distinction. This is a write endpoint whose failure mode was a silent
// success — the refusal IS the feature, and a moderator who typed a letter
// wrong has to be told that is what happened.
//
// FEDERATION. There is none today, so "not a local account" and "does not
// exist" are the same statement and user_exists() answers both. When a remote
// user can be invited, this check becomes a resolution step rather than a local
// lookup, and the wording below stops being true for a remote id — revisit it
// then rather than designing for it now.
const char* const kNoSuchAccount = "There is no account on this server with that id";

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
    // The target must name a real account before a membership row is written
    // for it. Set on the INVITE intent only: a kick already requires the target
    // to be in the room and an unban already requires it to be banned, so
    // neither can reach a write for an id with no account — and a BAN must
    // stay possible on one, because handle_register consults the ban list
    // before it creates anything, which makes a ban on an unregistered id a
    // reservation rather than a mistake. See kNoSuchAccount.
    bool require_target_exists = false;
    // An already-joined target means this request has nothing to do, so it
    // writes nothing and succeeds. Set on the INVITE intent only, and only for
    // an existing `join`: every other intent here is a DELIBERATE downgrade of
    // a joined member (kick, ban) and must keep working on one.
    //
    // Without it the state route carried the same defect as the dedicated
    // invite endpoint. classify_transition folds "invite" and "join" into one
    // intent that asserts nothing about `before`, so
    // PUT /state/m.room.member/{user} with {"membership":"invite"} fell through
    // to the unconditional set_membership below and demoted a joined member —
    // the same bug, the same room, a different URL, reachable by any Matrix
    // client that writes member state directly instead of using /invite.
    bool no_op_on_existing_join = false;
    // Stamps kRemovedByKey onto the member event this writes, so /join can tell
    // "a moderator removed you" from every other way a row reads `leave`.
    // See kRemovedByKey for why the sender is not enough on its own.
    bool records_removal = false;
    // THE DM RULE, carried by the intent rather than by the endpoint. nullptr
    // means "this act is legitimate in a direct room"; any other value is the
    // sentence to refuse with.
    //
    // WHY IT LIVES HERE. refuse_on_direct_room already guarded POST
    // /rooms/{id}/invite, and the generic state route had no equivalent: its
    // deny-list of state types named bsfchat.room.category, .type,
    // m.room.join_rules and bsfchat.channel.permissions but NOT m.room.member,
    // so a member write for somebody else fell straight through to
    // apply_membership_moderation. `{"membership":"invite"}` and
    // `{"membership":"join"}` both classify to invite_intent(), which asks for
    // room-scoped MANAGE_CHANNELS and nothing else — so a participant in a DM
    // who held that flag could add a third account to it, and the join spelling
    // force-joined them outright with the whole backlog. Exactly the drift this
    // struct exists to stop, in the one rule that had not been moved onto it
    // yet.
    //
    // DEFAULTS TO REFUSING, and that is the point rather than an accident.
    // A rule spelled out per-intent is a rule a fifth intent can be added
    // without, which is how this gap opened in the first place; defaulting the
    // other way means the next membership act somebody invents is refused on a
    // DM until a person has thought about it and written down why it should
    // not be. Same argument as state_gate_for's closed table below.
    const char* direct_room_refusal = "That cannot be done in a direct message";
    const char* verb = "";           // "ban"/"unban"/"kick"/"invite", for messages
};

// The sentence POST /rooms/{id}/invite has always refused with, and now also
// the one the state route refuses the same act with. UNCHANGED text: the
// client's add-member dialog matches on it (ChannelInviteModel::explainFailure)
// alongside the errcode, so it is a contract, not a message.
const char* const kInviteIntoDirectRoom = "Cannot invite someone into a direct message";

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
    // ALLOWED IN A DIRECT MESSAGE, and it has to be. A ban is not an act on
    // this room — it is an act on the ACCOUNT, and the membership rows it
    // rewrites (project_membership_everywhere, every room the target has a row
    // in) are a projection of that one decision. Refusing it on a direct room
    // would leave a banned account still joined to every DM it was in, holding
    // the backlog and able to go on reading it: the same blind spot the
    // server-wide ban list was added to close, reopened one room type at a
    // time.
    //
    // It also has to work FROM a direct room, which is where the gesture
    // actually happens: `room_id` here is only the room the request arrived
    // through, and the person you need to ban is usually the person in the DM
    // window you are looking at.
    i.direct_room_refusal = nullptr;
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
    // Allowed on a direct room for the same reason a ban is, and it is the
    // mirror of it: a rule that let the ban reach a DM but not the unban would
    // make a ban permanent there, which is the shape handle_unban exists to
    // stop ("a trail that reads as if nobody is ever forgiven").
    i.direct_room_refusal = nullptr;
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
    i.records_removal = true;
    // REFUSED on a direct room, unlike ban and unban, and the difference is
    // scope rather than severity. A kick touches exactly one room, so in a DM
    // it means "eject the other participant from our two-person conversation"
    // — which leaves a one-member direct room they cannot come back to, since
    // invites into a DM are refused and handle_join refuses a non-member of a
    // direct room. It is also gated on KICK_MEMBERS at SERVER scope, so it is
    // a server moderation power, and refuse_on_direct_room already says what
    // that must not buy: "a role that lets someone run the SERVER must not let
    // them run somebody's private conversation."
    //
    // Nothing legitimate is lost. Wanting out of a DM is LEAVING it, which is
    // self-membership and never reaches this function at all — handle_leave,
    // and the state route's own `state_key == *user_id` branch, which returns
    // long before the moderation delegation. Wanting the other person gone
    // from the server is a ban, which is allowed above.
    i.direct_room_refusal = "Cannot remove someone from a direct message";
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
    // The state route reaches this for membership "join" as well as "invite",
    // and that branch FORCE-JOINS — it was the worse half of the phantom-row
    // bug, because an invite row at least stays out of the joined-member counts
    // and the presence sweep while a join does not.
    i.require_target_exists = true;
    // See the field: this is the only intent that can be asked for a state the
    // target is already in, and the only one whose write would WEAKEN it.
    i.no_op_on_existing_join = true;
    // The rule POST /rooms/{id}/invite has always enforced and this route did
    // not. Same sentence at both doors, from one constant, so a reword cannot
    // reach one client path and miss the other.
    i.direct_room_refusal = kInviteIntoDirectRoom;
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
    //
    // user_exists() gates the OVERRIDE and nothing else, which is the whole of
    // the distinction. Banning an id that has not been registered is a
    // legitimate reservation — handle_register consults the ban list before it
    // creates anything — so the `server_bans` row is written either way and
    // that table deliberately has no foreign key to `users`. But this override
    // is the one place a ban INVENTS a membership row rather than rewriting
    // one, and inventing it for an account that does not exist is how a ban
    // produced a phantom member. With no account there is also nothing to
    // rewrite: the loop above found no rows, so this returns having written
    // nothing, and the audit record still names the room. See kNoSuchAccount.
    if (only_when.empty() && !origin_room.empty() && store_.user_exists(target_user) &&
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

    // The DM rule, applied once for every door into this function — see
    // MembershipIntent::direct_room_refusal for which acts it covers and why
    // ban and unban are not among them.
    //
    // ORDERED ABOVE THE PERMISSION CHECK, like the guard on the dedicated
    // invite endpoint, because it is structural: no permission makes it false.
    // That ordering discloses nothing, which is the usual objection to putting
    // anything above a permission test here — every caller that reaches this
    // function has already passed an is_room_member check at the endpoint it
    // came through, so it is a participant in the DM and already knows the room
    // is one.
    if (intent.direct_room_refusal && store_.is_direct_room(room_id)) {
        refusal.message = intent.direct_room_refusal;
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
    // Ordered here for the same reason as the two above, and it is load-bearing
    // for this one in particular: below the permission and rank checks, an
    // ordinary member's refusal is identical whether or not the id exists.
    if (intent.require_target_exists && !store_.user_exists(target_user)) {
        refusal.message = kNoSuchAccount;
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

    // Nothing to do. Ordered here — after every refusal, before every write —
    // so an unauthorised caller still gets the refusal it would have got, and
    // no caller can use this shortcut to skip a check.
    //
    // Answers with the id of the member event that ALREADY says so, rather than
    // an empty string: the state route's contract is "here is the event that
    // holds the state you asked for", and that event exists. No new event and
    // no audit record, for the reason the bot invite gives — a duplicate join
    // event renders as the member arriving twice, and a record of a change that
    // did not happen is worse than no record.
    if (intent.no_op_on_existing_join && before == membership::kJoin) {
        if (auto existing = store_.get_state_event(room_id, std::string(event_type::kRoomMember),
                                                   target_user)) {
            ok.event_id = existing->event_id;
        }
        return ok;
    }

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
        // Recorded from the INTENT, like everything else in this function, so the
        // marker cannot disagree with which act was authorised — the same reason
        // the permission, the scope and the rank check are read from here rather
        // than from the URL the request arrived at.
        if (intent.records_removal) content[std::string(kRemovedByKey)] = actor;
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
        std::string type;
        if (body.value("is_category", false)) {
            type = room_type::kCategory;
        } else if (body.value("voice", false)) {
            type = room_type::kVoice;
        } else {
            type = room_type::kText;
        }
        emit_state_event(room_id, *user_id, std::string(event_type::kRoomType), "",
                         json{{"type", type}});
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

        // A bot named here JOINS, exactly as POST /rooms/{id}/invite makes it
        // join. That rule exists because a bot has no human to accept an
        // invite, and it was added to handle_invite without being added here —
        // so creating a channel with a bot in `invite` left it sitting pending
        // while the documentation said inviting a bot joins it immediately.
        // The comment above still claimed this path "matched handle_invite"
        // after the two had diverged.
        const bool invitee_is_bot = bot::is_bot_user_id(invitee);
        const auto state = (is_direct || invitee_is_bot) ? membership::kJoin
                                                         : membership::kInvite;
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

    // A kick has to mean something, and this is the only thing that makes it
    // mean anything.
    //
    // Before this check, `kick` set membership='leave' and the target was back
    // with one empty POST to this endpoint — no body, no prerequisite. The
    // join_rule below could never stop them, because it is not a privacy control
    // on this deployment: the client hardcodes visibility="public" for every
    // channel it creates and expresses privacy as an @everyone DENY VIEW_CHANNEL
    // override instead (see docs/membership-vs-visibility.md), so EVERY channel,
    // including every "private" one, has join_rule "public" and that branch
    // always passes. A moderator's only working remedy was a server-wide ban,
    // which nukes every channel and every session. The middle rung of the ladder
    // did not exist.
    //
    // Scoped to this room, deliberately: a kick is a per-channel act and must not
    // become a soft server ban. The server-wide one is the check at the top.
    //
    // A VOLUNTARY leave is untouched, which matters more here than it would
    // elsewhere: auto-join puts every user in every channel, so leaving is how
    // somebody hides a channel they do not want, and it has to stay reversible.
    // was_removed_by_moderator distinguishes the two.
    //
    // The way back in is POST /rooms/{id}/invite, which writes membership
    // 'invite' and lets the next join through. That is a deliberate act by
    // somebody holding MANAGE_CHANNELS, which is what un-kicking should be.
    if (was_removed_by_moderator(store_, room_id, *user_id)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden(
            "You were removed from this channel and cannot rejoin unless you are invited "
            "back").to_json().dump(), "application/json");
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
    // Declining an invite is a leave. Matrix has no separate endpoint for it,
    // and this used to be `is_room_member`, which is join-only — so an invitee
    // could accept but not refuse, and a client's Decline button would have had
    // nothing to call. It only became reachable once /sync started telling
    // people they had been invited at all.
    //
    // Enumerated rather than "anything but leave": writing 'leave' over a 'ban'
    // row would quietly lift the ban, and 'knock' is not a membership this
    // server issues.
    const auto current = store_.get_membership(room_id, *user_id);
    if (current != std::string(membership::kJoin) && current != std::string(membership::kInvite)) {
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

    // Membership is not the answer to "which rooms may this user be told
    // about" — see auth/RoomVisibility.h. Returning it raw made this endpoint a
    // complete index of every private channel on the server: ids only, since
    // /messages, /state and /members each gate on VIEW_CHANNEL, but an id is
    // what you need to ask any of them, and the existence and count of the
    // private channels is itself the disclosure.
    //
    // One engine for the whole list. Per-room construction would re-read the
    // server roles and this user's role assignment once per room, all of it
    // serialised behind the store's single mutex.
    PermissionsEngine perms(store_, config_);
    auto rooms = visible_joined_rooms(store_, perms, *user_id);
    res.set_content(json{{"joined_rooms", rooms}}.dump(), "application/json");
}

void RoomHandler::handle_channel_directory(const httplib::Request& req, httplib::Response& res) {
    auto user_id = authenticate(store_, req.get_header_value("Authorization"));
    if (!user_id) {
        res.status = 401;
        res.set_content(auth_error(req.get_header_value("Authorization")).to_json().dump(),
                        "application/json");
        return;
    }

    // One engine for the whole sweep, same as /joined_rooms: this endpoint
    // evaluates a permission per room by construction, so a per-room engine
    // would re-read the server roles and this caller's role assignment once per
    // room, all of it serialised behind the store's single mutex.
    //
    // No rate limiter, deliberately. A per-request sweep over every room reads
    // like something that wants one, and the measurement says otherwise: on a
    // 300-channel server this answers in ~13 ms, against ~11 ms for
    // /joined_rooms and ~185 ms for the initial /sync that every client makes
    // on connect — and neither of those is limited. A limiter here would be the
    // only one on a read path, would throttle exactly the call a channel picker
    // makes once per page load, and would not be the cheapest lever an
    // authenticated attacker has. If read-path limiting is wanted it belongs in
    // the middleware across /sync, /messages and this together, not bolted onto
    // whichever endpoint was written last.
    PermissionsEngine perms(store_, config_);
    auto entries = visible_channel_directory(store_, perms, *user_id);

    // `category_id` is present only when it has a value, rather than sent as
    // "" — a caller testing `if entry.get("category_id")` and a caller testing
    // `"category_id" in entry` then agree, and neither can accidentally file a
    // top-level channel under a category whose id is the empty string.
    json channels = json::array();
    for (const auto& e : entries) {
        json j{{"room_id", e.room_id},
               {"name", e.name},
               {"type", e.type},
               {"joined", e.joined}};
        if (!e.category_id.empty()) j["category_id"] = e.category_id;
        channels.push_back(std::move(j));
    }
    res.set_content(json{{"channels", std::move(channels)}}.dump(), "application/json");
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
        json content = {{"membership", member_membership}};
        // This endpoint synthesises member content from the membership table
        // rather than serving the stored events, so it does NOT go through
        // read_event_row and does not inherit the bot flag from there. Derived
        // the same way and from the same helper, so the roster a client loads
        // here agrees with the one it gets from /sync.
        //
        // Without this the badge would depend on how the client happened to
        // learn about a user — present on a live join, absent in the roster
        // fetched at startup — which is worse than not having the flag at all.
        if (bot::is_bot_user_id(member_id)) {
            content[std::string(bot::kProfileKey)] = true;
        }
        chunk.push_back({
            {"type", event_type::kRoomMember},
            {"state_key", member_id},
            {"content", std::move(content)},
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
    // ── EVERY REFUSAL BELOW CARRIES A refusal::k* CODE ───────────────────
    //
    // This endpoint answers seven genuinely different situations with one
    // status and one errcode, and the client's add-member dialog has to give
    // seven different pieces of advice. Until now the only thing that told
    // them apart was the sentence, so ChannelInviteModel::explainFailure
    // matched SUBSTRINGS of it — which meant a reword here silently changed
    // client behaviour, and an eighth refusal could be swallowed by an
    // earlier fragment.
    //
    // The sentences below are UNCHANGED, deliberately: an older client is
    // still matching them and has to keep working against this server. The
    // code is additive, and a client that does not recognise one falls back
    // to showing the sentence (protocol/include/bsfchat/ErrorCodes.h).
    //
    // NOTHING HERE DISCLOSES MORE THAN IT DID. Each code says exactly what
    // its own sentence already said, one for one — no refusal that was
    // byte-identical to another becomes distinguishable. The one that would
    // matter is the existence check below, and its safety is the ORDERING
    // (see kNoSuchAccount), which this does not touch: a caller who fails
    // MANAGE_CHANNELS gets kInviteNoPermission for a real id and a fictional
    // one alike, as TheRefusalDoesNotSayWhichKindOfWrongIdItWas and
    // AnUnprivilegedCallerLearnsNothingAboutWhetherAnAccountExists pin.
    if (!store_.is_room_member(room_id, *user_id)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("Not a member of this room",
                                               refusal::kInviteNotInRoom).to_json().dump(),
                        "application/json");
        return;
    }
    // Even a participant cannot widen a DM: "only the two of us" is the whole
    // guarantee, and a third member would also be handed the entire backlog.
    //
    // ASKED OF THE INTENT rather than decided here, because this endpoint is
    // the one door into a membership write that does NOT route through
    // apply_membership_moderation — it carries seven refusals the client tells
    // apart, and the bot branch below, so it keeps its own body. What it must
    // not keep is its own copy of the RULE: that is how the generic state route
    // ended up enforcing a different one (see direct_room_refusal). One field
    // decides for both doors, and flipping it flips both.
    if (const auto* dm_refusal = invite_intent().direct_room_refusal;
        dm_refusal && refuse_on_direct_room(store_, res, room_id, dm_refusal,
                                            refusal::kInviteDirectRoom)) {
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
        res.set_content(MatrixError::forbidden("Insufficient permissions to invite",
                                               refusal::kInviteNoPermission).to_json().dump(),
                        "application/json");
        return;
    }

    // Check target user is not already banned
    auto target_membership = store_.get_membership(room_id, target_user);
    if (target_membership == "ban") {
        res.status = 403;
        res.set_content(MatrixError::forbidden("User is banned from this room",
                                               refusal::kInviteTargetBannedRoom).to_json().dump(),
                        "application/json");
        return;
    }
    // The per-room check above is not enough on its own: a channel created AFTER
    // the ban has no membership row for the banned user, so get_membership returns
    // "leave" and the invite would go through. The ban list is the thing that
    // knows, and it is the only thing that keeps working as channels come and go.
    if (store_.is_server_banned(target_user)) {
        res.status = 403;
        res.set_content(MatrixError::forbidden("User is banned from this server",
                                               refusal::kInviteTargetBannedServer).to_json().dump(),
                        "application/json");
        return;
    }

    // The target has to be somebody. Without this the endpoint answered 200 for
    // an id nobody holds and left a membership row behind for it — see
    // kNoSuchAccount for what the row does and for why this refusal is allowed
    // to be specific about the reason.
    //
    // Above the bot branch, so one check covers both: is_bot() reads users.kind
    // and so implies existence for a real bot, while a FICTIONAL @bot_* id
    // fails it and falls through to the human path. That is the only reason the
    // reported bug wrote an invite row rather than a join — and nothing should
    // be one edit away from emitting a join event whose sender does not exist.
    //
    // Below the two ban checks, so a pre-ban on an unregistered id keeps
    // answering "banned from this server", which is both true and the more
    // actionable of the two.
    if (!store_.user_exists(target_user)) {
        res.status = 403;
        // ONE code for all three shapes of wrong id, exactly as there is one
        // sentence for all three — see kNoSuchAccount. Three codes would
        // classify the namespace for whoever wanted that, which is the thing
        // the single wording exists to refuse.
        res.set_content(MatrixError::forbidden(kNoSuchAccount,
                                               refusal::kInviteNoSuchAccount).to_json().dump(),
                        "application/json");
        return;
    }

    // Inviting a BOT joins it immediately, rather than leaving an invite nobody
    // will ever accept.
    //
    // VISIBILITY IS NOT THE REASON, though it used to be. This branch was first
    // justified by a bot being unable to SEE an invite: SyncResponse carried
    // only a `join` map, so an invite row for a bot was unreachable through
    // every endpoint it polled. feat/sync-invites has since landed —
    // SyncResponse has rooms.invite, attach_pending_invites restates the
    // pending set on each delivered response, and get_events_since hands an
    // invitee their own m.room.member event — so a bot polling /sync would now
    // see a pending invite perfectly well. The behaviour is unchanged anyway,
    // because that was the weaker of the two reasons and the other one holds.
    //
    // THE REASON IS THAT NOTHING ACCEPTS. A bot has no human to accept, and no
    // bot implements acceptance: examples/python-bot's sync loop reads
    // rooms.join and nothing else, so there is no path by which it could notice
    // rooms.invite, let alone POST /join off the back of it. That is not an
    // oversight waiting to be fixed — it is the published contract. docs/bots.md
    // §3.1 tells bot authors "you write no invite-handling code at all", §11
    // lists the new rooms.invite section as explicitly irrelevant to bots, and
    // the SDK README says a bot never has a pending invite to find there.
    // Writing an invite row here would honour the letter of that promise and
    // break every bot written to it: the invite would be visible, ignored, and
    // the bot would simply never arrive — a silent failure for the operator,
    // which is the thing this branch exists to prevent. Seeing an invite and
    // acting on one are different capabilities; only the second would change
    // this decision, so revisit it if a bot SDK ever grows an accept path.
    //
    // rooms.invite is therefore empty for a bot in practice, because this is the
    // only writer of an invite row and it never writes one for a bot. The one
    // residue is historical: before the user_exists() check above, an invite to
    // a @bot_* id nobody held left a row behind, and create_bot writes `users`
    // and `bots` without touching room_members — so a bot created on such a
    // localpart starts life with a pending invite it will ignore forever.
    //
    // WHY THIS DOES NOT CONTRADICT THE AUTO-JOIN EXCLUSION. It will look like it
    // does, so: AutoJoin::join_user_to_room refuses bots, and must keep refusing
    // them. That exclusion is about the three UNTARGETED sweeps — every public
    // channel at account creation, every user when a channel is created, and
    // every (user, room) pair on every single boot via backfill_auto_join. Those
    // are automatic, server-wide, and repeat forever; a bot caught by them lands
    // in all 50 channels including ones created years later, silently, with
    // nobody having decided anything. THIS is the opposite in every respect: one
    // named bot, one named channel, requested explicitly by a person who just
    // passed the room's MANAGE_CHANNELS check, once. "A bot joins only on an
    // explicit invite or join" is the rule, and this is the explicit invite —
    // removing this would not strengthen the exclusion, it would just make the
    // invite path the thing that silently does nothing.
    //
    // Reached only AFTER every check above has passed: the inviter's membership,
    // the DM refusal, MANAGE_CHANNELS, the per-room ban and the server-wide ban.
    // Nothing here bypasses any of them — this changes what happens once they
    // pass, and only for a bot. Human invite semantics are untouched.
    if (store_.is_bot(target_user)) {
        auto bot = store_.get_bot(target_user);

        // A deactivated bot holds no tokens and cannot act, so joining it to a
        // channel would put a permanently silent member in the room and imply to
        // everyone else that something is listening. Consistent with the refusal
        // on rotating a deactivated bot: deactivation is final.
        if (bot && bot->deactivated_at) {
            res.status = 403;
            res.set_content(MatrixError::forbidden(
                "That bot is deactivated and cannot be added to a channel",
                refusal::kInviteTargetDeactivated).to_json().dump(),
                "application/json");
            return;
        }

        // Idempotent. A second invite is a success that writes nothing: no
        // duplicate join event for other clients to render as the bot arriving
        // twice, and no second audit record for an event that happened once.
        if (store_.is_room_member(room_id, target_user)) {
            res.set_content("{}", "application/json");
            return;
        }

        const auto before = store_.get_membership(room_id, target_user);

        store_.set_membership(room_id, target_user, std::string(membership::kJoin));
        // A real join event, sent BY the bot, exactly as the self-join path emits
        // one — so every other member sees the bot arrive through the ordinary
        // membership machinery rather than appearing out of nowhere at the next
        // full sync. member_event_content carries the bot's display name (and
        // nickname, if it has one), so it renders with a name from the first sync.
        emit_state_event(room_id, target_user, std::string(event_type::kRoomMember),
                         target_user,
                         member_event_content(store_, target_user,
                                              std::string(membership::kJoin)));

        // Audited at the action site, per AuditLog's contract. The ACTOR is the
        // inviter, not the bot: a bot in a channel is the result of a person
        // putting it there, and "who gave this bot access to that channel" is the
        // question the record exists to answer. Recorded as the membership
        // transition it is, through the existing vocabulary, so a filter by room
        // or by user finds it alongside every other membership change rather than
        // in a bot-specific dialect of its own.
        audit_membership_change(store_, *user_id, room_id, target_user, before,
                                std::string(membership::kJoin), "invite (bot auto-join)");

        res.set_content("{}", "application/json");
        get_logger()->info("User {} invited bot {} to room {}; joined immediately "
                           "(a bot has no human to accept an invite)",
                           *user_id, target_user, room_id);
        return;
    }

    // Idempotent for somebody who is ALREADY IN the channel, for the same reason
    // the bot branch above is: what the caller asked for already holds, so the
    // only thing left to decide is what to do with the request.
    //
    // Doing the write anyway was the bug, and it was a DEMOTION rather than a
    // harmless repeat. set_membership is a blind upsert, so an 'invite' written
    // over a 'join' row took a full member back down to an invitee, and every
    // projection that reads membership is join-only: the channel left their
    // /sync rooms.join and came back as a bare invite card with no timeline
    // (get_joined_rooms / get_invited_rooms), can_read_room started refusing
    // /state, /state/{type} and /members, sending a message and joining voice
    // answered "Not a member of this room", they dropped out of the presence
    // sweep and out of joined_member_count. None of it was audited, because the
    // human invite path writes no audit record at all — so a member could be
    // removed from a channel by a moderator clicking "add member", and the only
    // trace was an m.room.member event saying `invite`.
    //
    // The client's add-member dialog has been refusing this case out of its
    // roster cache since the dialog was built, purely because the server would
    // not (ChannelInviteModel). That guard is best-effort — a cache miss falls
    // through to here — so it was never the fix.
    //
    // 200 with an empty body, NOT a refusal. "Add this person to this channel"
    // when they are already in it is not an error in any UI that offers the
    // gesture over a list of people, which is why the bot branch answers this
    // way, and answering the same way here is what lets one client path handle
    // both. A refusal would also have to be a SEVENTH sentence behind this
    // endpoint's single M_FORBIDDEN errcode, which the client disambiguates by
    // matching on the text (ChannelInviteModel::explainFailure) — a contract
    // change for a case that is not a failure.
    //
    // JOIN ONLY, and this is the part to get right. Re-inviting is the
    // documented way to re-admit somebody a moderator kicked, and a kicked
    // user's row says 'leave', not 'join'. is_room_member() is join-only, so
    // this cannot fire for them and the write below still happens — which is
    // precisely what clears the removal, because was_removed_by_moderator reads
    // the CURRENT m.room.member event and the fresh invite content carries no
    // kRemovedByKey. Widening this to "has a membership row" or "is not banned"
    // would make every kick permanent while this endpoint went on answering
    // 200, with /join's refusal as the only symptom.
    // KickEnforcement.AnInviteAfterAKickReadmits is the test that says so.
    if (store_.is_room_member(room_id, target_user)) {
        res.set_content("{}", "application/json");
        get_logger()->info("User {} invited {} to room {}; already a member, nothing written",
                           *user_id, target_user, room_id);
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
    //
    // bsfchat.channel.permissions joins them (finding 6 of
    // docs/membership-vs-visibility.md). A DM has no channel access control:
    // its access control is that exactly two people are in it and nobody is
    // ever force-joined into one, which is the reason m.direct is derived
    // straight from membership and deliberately left unfiltered. An override
    // written onto a DM is not a weaker version of that rule, it is a second,
    // contradictory one — denying VIEW_CHANNEL on a DM hides it from
    // /joined_rooms and /sync while m.direct goes on listing it.
    //
    // A DENY-LIST ENTRY RATHER THAN AN ALLOW-LIST FOR DMs, deliberately, even
    // though this file argues the opposite way for state_gate_for below. The
    // two are not the same shape. A state type is scoped to the room it is
    // written in, so "refuse unless named" is safe there. Four of the types
    // this route accepts are NOT scoped to their room (bsfchat.server.info,
    // .roles, .screenshare and bsfchat.member.roles) —
    // bsfchat.server.screenshare in particular is a server-wide setting that
    // the client writes into whichever room happens to be active, which can be
    // a DM (ServerConnection::setScreenSharePolicy takes m_activeRoomId) — so
    // refusing everything unnamed on a DM would break server administration
    // from a DM window. What is wrong here is specifically per-CHANNEL
    // configuration on a room that is not a channel.
    // m.room.member is NOT in this list, deliberately, and its absence used to
    // be the bug rather than a decision. A DM refuses membership writes too,
    // but which ones depends on what the write MEANS — a ban has to reach a DM
    // and an invite must not — and that is a question only classify_transition
    // can answer. Adding m.room.member here would refuse all four; leaving it
    // out silently allowed all four. It is gated on the intent instead, in
    // apply_membership_moderation, which is also where the dedicated endpoints
    // get the same rule.
    if ((evt_type == std::string(event_type::kRoomCategory) ||
         evt_type == std::string(event_type::kRoomType) ||
         evt_type == std::string(event_type::kRoomJoinRules) ||
         evt_type == std::string(event_type::kChannelPermissions)) &&
        refuse_on_direct_room(store_, res, room_id,
                              "A direct message is not a channel and its structure cannot be changed")) {
        return;
    }

    // Changing an existing room's KIND is an act on the server's channel tree
    // rather than an edit inside one channel, so it carries rules of its own
    // below (the conversion gate) as well as a server SCOPE in the table. The
    // scope half is no longer expressed here — see state_gate_for.
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

    // Map the state event type to the permission flag that gates it — from a
    // CLOSED table. An unlisted type is refused.
    //
    // This used to be an if/else chain over three special cases with
    // MANAGE_CHANNELS as the fallback, so every type not named — including
    // types nobody has defined — was accepted, stored as room state, and
    // delivered to every member through /sync's state.events with content taken
    // verbatim from the request body.
    //
    // It is the state-route twin of the hole `send_gate_for` closed on the send
    // path, and the reasoning there applies unchanged: allowing by default is
    // what produced the hole, and adding a settable type should be a deliberate
    // edit to this table rather than something that happens by nobody thinking
    // about it. The auth audit excluded state events from its table on the
    // grounds that this route "has its own per-type authorisation" — it did, and
    // that authorisation was the thing the same document had just argued against.
    //
    // Two entries are deliberately ABSENT rather than forgotten:
    //   * m.room.create — written once, by the server, when the room is made. It
    //     names the room's creator, and there is no legitimate request that
    //     rewrites it.
    //   * m.room.member — never reaches here. Self-membership and moderation of
    //     another member both returned above, and the empty-state_key spelling
    //     names no target. Listing it would be listing a case that cannot occur.
    //
    // Severity of what this closes is low on its own — it needs MANAGE_CHANNELS,
    // and the worst outcome is attacker-shaped JSON in the state of a channel
    // you can already administer — but it is the shape that gets copied.
    //
    // EVERY SETTABLE TYPE NAMES FOUR THINGS, and there is no default for any of
    // them. `allowed` is the closed table described above. `required` is the
    // flag. `scope` is WHERE that flag is evaluated. `home` is where the
    // authoritative copy of the event lands.
    //
    // SCOPE IS IN THE TABLE BECAUSE THE SAME BUG HAPPENED THREE TIMES.
    //
    // A type whose effect is server-wide must be gated at server scope,
    // because `perms.can(user, room_id, FLAG)` lets that channel's overrides
    // contribute and `perms.can(user, kServerScope, FLAG)` does not — so a
    // per-channel ALLOW override, which is the natural way to give somebody
    // their own channel, is otherwise a lever on the whole deployment. That
    // sentence was written here twice already, as two named exceptions with
    // two long comments: `bsfchat.room.type`, whose room scope let one channel
    // grant be enough to retype any channel as a category, and
    // `bsfchat.server.screenshare` (finding 21 of
    // docs/audit-requests-2026-09.md), a server-wide media setting the client
    // writes into whichever room happens to be active.
    //
    // Both fixes were correct and neither generalised, so the third instance
    // was still here when the September 2026 permissions audit looked: F1,
    // `bsfchat.server.info`, evaluated in the room it was written in, which
    // made a channel-scoped MANAGE_SERVER override enough to rename the
    // deployment and replace its icon for every connected client. The comment
    // at the top of this function had NAMED `bsfchat.server.info` among the
    // types "NOT scoped to the room they are written in" since before the
    // second fix landed; the scope expression twelve lines below it simply did
    // not include it. A list of exceptions is a structure that has to be
    // remembered. A column is a structure that has to be filled in.
    //
    // `home` is the other axis and it is NOT the same question, which is why
    // the two were conflated for so long. kServerState means the write is
    // routed through write_server_scoped_state, which moves the authoritative
    // copy into server_state and audits it as a role change after parsing the
    // body as a role document. That is right for the role types and wrong for
    // `server.info` and `server.screenshare`: nothing reads server identity or
    // a screen-share cap out of server_state — the only reader in the system
    // is the client, off the sync mirror — so taking that branch would write a
    // row no read path consults and leave the copy clients actually obey
    // exactly where it is now. Server-WIDE and server-STORED are different
    // properties and every row below states both.
    enum class Scope { kRoom, kServer };
    enum class Home { kRoomState, kServerState };
    struct StateGate {
        bool allowed = false;
        permission::Flags required = 0;
        Scope scope = Scope::kRoom;
        Home home = Home::kRoomState;
    };
    const auto state_gate_for = [](const std::string& type) -> StateGate {
        // Channel structure and presentation: an edit INSIDE one channel,
        // evaluated in that channel, stored on it.
        if (type == event_type::kRoomName || type == event_type::kRoomTopic ||
            type == event_type::kRoomAvatar || type == event_type::kRoomJoinRules ||
            type == event_type::kRoomCanonicalAlias ||
            type == event_type::kRoomHistoryVisibility ||
            type == event_type::kRoomPowerLevels || type == event_type::kRoomPinnedEvents ||
            type == event_type::kRoomVoice || type == event_type::kRoomCategory ||
            type == event_type::kChannelSettings) {
            return {true, permission::kManageChannels, Scope::kRoom, Home::kRoomState};
        }
        // The room's KIND. Same flag as its siblings above, server scope: it
        // is a decision about the server's channel tree and about who may read
        // the conversation inside, not a presentation change.
        if (type == event_type::kRoomType) {
            return {true, permission::kManageChannels, Scope::kServer, Home::kRoomState};
        }
        // Who may do what IN THIS CHANNEL. Room scope is correct here — this
        // is the one type whose entire subject is the channel it is written in
        // — and it is exactly why it needs rules of its own beyond the flag:
        // see PermissionsEngine::may_write_channel_override, applied below.
        if (type == event_type::kChannelPermissions) {
            return {true, permission::kManageRoles, Scope::kRoom, Home::kRoomState};
        }
        // Who may do what ON THE SERVER. Server scope — a per-channel override
        // granting MANAGE_ROLES in one unimportant channel once let that user
        // rewrite every role on the server, including granting themselves
        // ADMINISTRATOR, because the role reader ignores room_id entirely — and
        // the authoritative copy lives in server_state.
        if (type == event_type::kServerRoles || type == event_type::kMemberRoles) {
            return {true, permission::kManageRoles, Scope::kServer, Home::kServerState};
        }
        // Server identity — the name and icon every client renders, which
        // ServerConnection writes into whichever room happens to be active and
        // applies from whichever room it arrives in. Server scope. F1.
        if (type == event_type::kServerInfo) {
            return {true, permission::kManageServer, Scope::kServer, Home::kRoomState};
        }
        // The deployment's screen-share ceiling. Same shape as server identity.
        if (type == event_type::kServerScreenShare) {
            return {true, permission::kManageChannels, Scope::kServer, Home::kRoomState};
        }
        return {};
    };

    // Evaluated here, applied below — the two m.room.member paths return before
    // the gate is consulted, which is why that type is not in the table.
    const auto gate = state_gate_for(evt_type);

    PermissionsEngine perms(store_, config_);
    // Both read straight off the table, so neither can disagree with it and
    // neither can be forgotten for a type added later. A server-scoped check
    // passes kServerScope, which is the empty room id: PermissionsEngine
    // applies no channel override to it, in either direction, so a per-channel
    // allow cannot grant the act and a per-channel deny cannot block it.
    const bool is_server_scoped = gate.home == Home::kServerState;
    const std::string perm_scope = gate.scope == Scope::kServer ? kServerScope : room_id;

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

    // The allowlist, applied before the permission test rather than after it.
    // ADMINISTRATOR short-circuits every flag inside PermissionsEngine::compute,
    // so an owner would still walk an unknown type straight through a check
    // ordered the other way round.
    if (!gate.allowed) {
        res.status = 403;
        res.set_content(MatrixError::forbidden(
            "State events of type '" + evt_type + "' cannot be set on a room")
                .to_json().dump(), "application/json");
        return;
    }
    if (!perms.can(*user_id, perm_scope, gate.required)) {
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

        if (new_room_type == room_type::kCategory &&
            previous_room_type != room_type::kCategory) {
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

        // ── THE CONTAINMENT RULE, applied to the third way this server hands
        //    out permissions ──
        //
        // MANAGE_ROLES at room scope used to be the WHOLE gate on this event,
        // and this event is a permission grant to a named principal. The other
        // two routes that do that — the role document and the role assignment
        // — have both carried a "you cannot grant what you do not hold" rule
        // and a rank rule for a while, for reasons written out at length in
        // auth/Permissions.h. This one carried neither, so F2 of
        // docs/audit-permissions-2026-09.md was: a delegated "builder" holding
        // MANAGE_ROLES in one channel wrote itself every channel-scoped flag
        // in that channel (delete it, redact anybody's messages, ping
        // @everyone), and wrote a DENY against accounts that outranked it.
        // Chained with F1 above it was a two-request path to renaming the
        // server, which is the exact sentence may_edit_role_definitions' own
        // comment says MANAGE_ROLES must not be.
        //
        // The rules live on PermissionsEngine rather than here, deliberately.
        // This is currently the only writer, and a rule that lives at its only
        // call site is a rule the second call site does not get — which is the
        // history of this whole function.
        //
        // The previous override is read HERE rather than inside the engine
        // because the audit capture two lines up has already paid for that
        // read. `before` defaults to allow = 0, deny = 0, which is exactly
        // what "there is no override" means to compute().
        ChannelPermissionOverride before;
        if (existing) from_json(existing->content.data, before);
        ChannelPermissionOverride proposed;
        from_json(content, proposed);

        auto verdict = perms.may_write_channel_override(*user_id, room_id, state_key, before,
                                                        proposed);
        if (!verdict.allowed) {
            get_logger()->warn("Refused channel override by {} on {} ({}): {}", *user_id,
                               room_id, state_key, verdict.reason);
            res.status = 403;
            res.set_content(MatrixError::forbidden(verdict.reason).to_json().dump(),
                            "application/json");
            return;
        }
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
