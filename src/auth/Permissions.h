#pragma once

#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace bsfchat {

class SqliteStore;
struct Config;

// Computes effective permissions for a (user, channel) pair using the server
// roles, per-user role assignments, and per-channel allow/deny overrides.
// Mirrors Discord's documented precedence:
//   base = OR of every role's permissions for the user (incl. @everyone)
//   if ADMINISTRATOR bit set → return all flags
//   apply @everyone channel override
//   apply each role's channel override, in position-ascending order
//   apply user-specific channel override
class PermissionsEngine {
public:
    PermissionsEngine(SqliteStore& store, const Config& config);

    permission::Flags compute(const std::string& user_id, const std::string& room_id);

    bool can(const std::string& user_id, const std::string& room_id, permission::Flags p) {
        return (compute(user_id, room_id) & p) == p;
    }

    // The server's role definitions, memoised for this request. Same reasoning
    // as roles_of(): the send path needs to look up a named role's `mentionable`
    // flag, and this engine has almost certainly already read the roles to
    // answer a permission question about the same request.
    const std::vector<ServerRole>& roles() { return server_roles(); }

    // The role ids assigned to `user_id`, memoised for this request.
    //
    // Exposed for the mention path, which has to ask "does this member hold one
    // of the roles the message named?" once per push candidate. Going through
    // the engine rather than the store directly is the point: the caller has
    // already asked this engine whether the same user has VIEW_CHANNEL in the
    // same room, so the role read is a cache hit and the role check is free.
    // Calling store.get_member_role_ids() in that loop instead would be one
    // server_state query per candidate, under the store's global mutex, on the
    // send path.
    //
    // Does NOT include @everyone: this is the assignment as stored, not the
    // effective set. compute() adds @everyone itself.
    const std::vector<std::string>& roles_of(const std::string& user_id) {
        return member_role_ids(user_id);
    }

    // Returns the highest role position the user holds. Used for hierarchy
    // checks like "mods can't modify admins." @everyone is position 0.
    //
    // SELF-ASSIGNABLE ROLES DO NOT COUNT. A role anyone may take cannot also
    // confer rank, or rank stops meaning anything: a "Boss pings" role sitting
    // at position 50 so it hoists above the moderators would, the moment
    // someone clicked it in the picker, make them un-kickable and un-bannable
    // by every moderator on the server — outranks() is the whole of that gate.
    // Excluding them here is what lets `position` stay a free display choice on
    // a role that is, by construction, not a privilege. No existing role is
    // affected: the flag defaults to false and nothing on an upgraded server
    // has it set.
    int highest_role_position(const std::string& user_id);

    // ── THE CONTAINMENT RULE ────────────────────────────────────────────
    //
    // ONE SENTENCE, STATED ONCE, APPLIED EVERYWHERE THE SERVER HANDS OUT OR
    // TAKES AWAY ACCESS:
    //
    //     Nobody may confer access they do not hold, and nobody may strip
    //     access from a principal that holds more than they do.
    //
    // Both halves already existed in this file, written out twice for the role
    // document (`may_edit_role_definitions`: "you cannot grant a role a
    // permission you do not hold yourself") and for the role assignment
    // (`may_assign_roles`: "nothing at or above your own rank"). What they had
    // never been applied to is the THIRD way this server hands out permissions,
    // the per-channel override — and the omission was not an oversight about
    // one route, it was the rule never having been given a name or a home. The
    // September 2026 permissions audit (docs/audit-permissions-2026-09.md)
    // found three separate escalations that are all this one sentence going
    // unenforced:
    //
    //   F2  MANAGE_ROLES in a single channel was the whole gate on writing
    //       `bsfchat.channel.permissions`, so a delegated "builder" wrote
    //       itself every channel-scoped flag in that channel and a DENY
    //       against an account that outranked it.
    //   F1  `bsfchat.server.info` was evaluated at ROOM scope, so the flag F2
    //       handed out was a two-request path to renaming the deployment.
    //   F6  `outranks()` measured ROLE POSITION ONLY, and BotHandler.h
    //       prescribes the per-channel override as THE way to scope a bot —
    //       which `handle_create_bot` reinforces by writing every new bot an
    //       empty role assignment. A correctly scoped bot therefore sat at
    //       position 0 forever and every MANAGE_BOTS holder at position >= 1
    //       "outranked" it, which bought them a non-expiring credential for an
    //       account that can read channels they are themselves denied.
    //
    // THE REASON THEY ARE FIXED TOGETHER rather than one patch each: they are
    // one defect seen from three angles, and three separate patches is how the
    // same defect reaches a fourth instance. `handle_set_state` had already
    // grown this fix twice as a named exception (`bsfchat.room.type`, then
    // `bsfchat.server.screenshare`), each with a comment explaining the
    // principle and neither generalising it — so the third instance, F1, was
    // sitting twelve lines below a comment that NAMED `bsfchat.server.info` as
    // one of the types "NOT scoped to the room they are written in". The scope
    // half of the answer is therefore not a third exception but a table:
    // RoomHandler's state gate now names a scope for every settable type and
    // there is no default to be wrong about. The access half is the two
    // functions below.
    //
    // ADMINISTRATOR and the synthetic @server actor are exempt from both
    // halves, as they are from every other check here. That exemption is not
    // an opening: `compute()` takes the administrator short-circuit from the
    // ROLE BASE, before any channel override is applied, so an override cannot
    // manufacture one.

    // Flags `subject` can exercise SOMEWHERE THAT `actor` CANNOT, because of
    // how some channel is configured. Zero means the actor's channel access
    // contains the subject's — which is the property that makes it safe to
    // moderate them, or to be handed their credentials.
    //
    // WHAT IT DELIBERATELY DOES NOT MEASURE is the server-wide difference
    // between the two, `compute(subject, "") & ~compute(actor, "")`. That gap
    // is the ROLE half of seniority and this server governs it with `position`,
    // deliberately: a moderator holding KICK_MEMBERS does not hold
    // MANAGE_MESSAGES, and demanding a superset there would mean nobody could
    // ever moderate anybody. So the role gap is subtracted out and what
    // remains is exactly what a CHANNEL's configuration adds on top.
    //
    // Only rooms that carry a `bsfchat.channel.permissions` event are examined,
    // and that is a completeness argument rather than an optimisation: in a
    // room with no overrides `compute(x, room)` IS `compute(x, "")` for every
    // x, so the difference there is the role gap by construction and subtracts
    // to zero. A DM contributes nothing for the same reason — compute() clears
    // overrides on a direct room before applying any of them.
    permission::Flags channel_access_excess(const std::string& subject_id,
                                            const std::string& actor_id);

    // Returns true if `actor` outranks `target`.
    //
    // TWO HALVES, BOTH REQUIRED. The actor's highest role position must be
    // strictly greater than the target's, AND the actor's channel access must
    // contain the target's (`channel_access_excess` == 0). Used to gate
    // kick/ban/nickname/role-assignment/bot-administration against principals
    // the actor is not senior to.
    //
    // THE SECOND HALF IS F6 OF THE AUDIT and it is why this is not simply a
    // question about roles. A scoped bot holds no roles at all — that is what
    // scoping a bot MEANS on this server — so position alone compared 0 against
    // 0 and answered "yes, you outrank it" to every delegated MANAGE_BOTS
    // holder on the server. Rotating that bot's token then handed them a
    // non-expiring credential for an account that reads channels they are
    // explicitly denied. Rank had to learn to measure the thing a bot actually
    // holds.
    //
    // IT IS STRICTLY MORE RESTRICTIVE THAN THE OLD RULE, in every caller: this
    // function only ever returns false where it used to return true, and every
    // call site treats false as a refusal. It cannot open anything.
    //
    // IT DOES CHANGE BEHAVIOUR, and the change is worth stating plainly rather
    // than discovering: a delegated moderator can no longer kick, ban, rename
    // or reassign the roles of a member who can see a channel the moderator
    // cannot. That is the intended reading of the sentence at the top — a
    // principal with access you do not have is not below you — and it matches
    // the rule `handle_set_state` already applies to channels themselves ("You
    // may not restructure a channel you are not allowed to open"). The way out
    // of it is the same as ever: hold ADMINISTRATOR, or be let into the
    // channel.
    bool outranks(const std::string& actor_id, const std::string& target_id);

    // Why a role change was refused. Empty `reason` means it was allowed.
    struct RoleChangeVerdict {
        bool allowed = true;
        std::string reason;
        explicit operator bool() const { return allowed; }
    };

    // The hierarchy rules for the two role-editing state events.
    //
    // MANAGE_ROLES alone used to be the whole gate on both of them, with no
    // rank check anywhere on the path — so anyone holding that one flag could
    // PUT their own bsfchat.member.roles with {"role_ids":["admin"]} and
    // become a full ADMINISTRATOR, or rewrite bsfchat.server.roles to put
    // ADMINISTRATOR on @everyone. MANAGE_ROLES is the permission an owner
    // hands to a trusted-but-not-admin "builder"; it must not be a one-request
    // path to owning the server. This header's own contract already named role
    // assignment as something outranks() gates; it was the one case that did
    // not use it.
    //
    // Holders of ADMINISTRATOR (and the synthetic @server actor) are exempt,
    // the same way they short-circuit every other check.

    // May `actor` set `target`'s role assignment to `new_role_ids`?
    RoleChangeVerdict may_assign_roles(const std::string& actor_id,
                                       const std::string& target_id,
                                       const std::vector<std::string>& new_role_ids);

    // May `actor` replace the server's role definitions with `proposed`?
    //
    // THE ONE AUTHORITY for a role-document change. The wholesale
    // `bsfchat.server.roles` PUT calls it, and so does every endpoint in
    // api/RoleHandler.cpp — those endpoints build the proposed document
    // server-side from a delta and hand it to this function rather than
    // carrying their own opinion about who may do what. A create/edit/delete
    // route with its own check is how one of the rules below eventually gets
    // dropped on one path.
    RoleChangeVerdict may_edit_role_definitions(const std::string& actor_id,
                                                const std::vector<ServerRole>& proposed);

    // Invariants a role document must satisfy WHOEVER is writing it —
    // administrators and the synthetic @server actor included. Called first
    // from may_edit_role_definitions, before any exemption.
    //
    // These are not privilege rules, they are coherence rules about what a role
    // list is allowed to say, and the important one is about `self_assignable`.
    // A self-assignable role may carry no permission bit @everyone does not
    // already carry, so taking it or dropping it cannot change the holder's
    // server-wide capabilities at all. That is the answer to the obvious attack
    // on the feature — "mark a role MANAGE_ROLES and self-assignable, then
    // every member is a role admin" — and it has to bind an administrator too,
    // because "I am allowed to do anything" is not a reason to be allowed to
    // publish a document whose meaning is "everyone may promote themselves".
    // An opt-in role that should unlock a CHANNEL still can: that is a
    // per-channel override keyed on the role id, which is a deliberate act by
    // someone holding MANAGE_ROLES in that channel, not a server-wide grant
    // handed out by a checkbox.
    static RoleChangeVerdict validate_role_document(const std::vector<ServerRole>& proposed);

    // May `actor` add this role to themselves, or take it back off, with no
    // MANAGE_ROLES and no rank?
    //
    // Deliberately NOT a relaxation of may_assign_roles — a separate question
    // with a separate answer. may_assign_roles asks "does the actor outrank
    // this?", and for an ordinary member the answer is permanently no: they sit
    // at position 0, every role sits at position >= 0, and the rule is "nothing
    // at or above your own rank". There is no position an opt-in role could be
    // given that would make that check pass, so a self-service picker is
    // impossible until the rank check is bypassed. This bypasses it, and pays
    // for the bypass with validate_role_document's containment rule, re-checked
    // here against the CURRENT document rather than trusted from write time.
    //
    // The same verdict governs REMOVAL, which is not a weaker act than
    // addition: a role can carry channel DENY overrides, so "muted" is a role,
    // and letting a member shed any role they happen to hold would be letting
    // them unmute themselves. You may drop exactly what you were allowed to
    // take.
    //
    // `adding` distinguishes taking a role from dropping one, because exactly
    // one rule differs. The containment rule — a self-assignable role's
    // permissions must be a subset of @everyone's — is a rule about what
    // TAKING a role may grant you. Applied to removal it is a trap: a member
    // holding a role whose permissions drifted outside @everyone's (because
    // @everyone was narrowed afterwards) could not shed it, and no admin path
    // helps them, because self-assignment is the only way that role moves.
    // Dropping a role cannot grant anything, so the check has no work to do
    // there.
    //
    // Everything else still binds both directions, which is the point of the
    // paragraph above: self_assignable itself is re-checked on removal so a
    // mute role cannot be shed.
    //
    // A BOT MAY NOT USE THIS PATH AT ALL, in either direction. The containment
    // rule that pays for the rank bypass caps an opt-in role at @everyone's
    // permissions — and @everyone's permissions are exactly what a scoped bot
    // was not given, so for a bot this would be a one-request way out of its
    // scoping with no privilege required. The refusal is first in the function.
    RoleChangeVerdict may_self_assign_role(const std::string& actor_id,
                                           const std::string& role_id,
                                           bool adding);

    // May `actor` replace the `bsfchat.channel.permissions` override at
    // `state_key` in `room_id`, turning `before` into `proposed`?
    //
    // THE ONE AUTHORITY for a channel override, in the same sense and for the
    // same reason `may_edit_role_definitions` is the one authority for a role
    // document: there is exactly one route that writes this event today
    // (RoomHandler::handle_set_state), the audit's recommendation was
    // explicitly that the rules live here "so that a future second writer
    // cannot skip them", and a second writer with its own opinion is how one
    // of the two rules below eventually gets dropped on one path. It therefore
    // re-checks MANAGE_ROLES itself rather than trusting the caller's gate.
    //
    // `before` is the override as it stands (default-constructed — allow = 0,
    // deny = 0 — when there is none). Every rule below is scoped to what the
    // write CHANGES, which is what keeps two things legal that must stay
    // legal: echoing an override back unmodified, and clearing a grant.
    //
    // ── Rule 1, containment ──
    // Every bit the write touches, in either direction, must be a bit the
    // actor holds IN THAT CHANNEL.
    //
    //     changed = (proposed.allow ^ before.allow) | (proposed.deny ^ before.deny)
    //     refuse unless (changed & ~compute(actor, room_id)) == 0
    //
    // A symmetric difference rather than "what the edit adds", because there
    // are FOUR edits here and the audit's sketch named two of them. Access
    // GOES UP when an allow appears (`allow & ~before.allow`) and equally when
    // a deny DISAPPEARS (`before.deny & ~deny`) — the second is the one that
    // looks like a removal and is a grant. Access GOES DOWN when a deny
    // appears and equally when an allow is taken back. All four are statements
    // about a permission, and the actor has no standing to make any of them
    // about a permission that is not theirs in this channel.
    //
    // ADMINISTRATOR may never be ADDED to `allow`, by anybody, and that is a
    // coherence rule rather than a privilege rule — the administrator
    // short-circuit is taken from the role base before overrides are applied,
    // so the bit means literally nothing here and its presence is always
    // either a misunderstanding or an attempt. Removing or echoing one that a
    // previous build stored stays legal, so no channel is left unfixable.
    //
    // ── Rule 2, rank ──
    // A write that TAKES ACCESS AWAY from a named principal needs the same
    // seniority every other act against a principal needs on this server.
    //
    //   * `user:<target>` — refused unless `outranks(actor, target)`, the same
    //     test may_assign_roles and handle_put_nickname apply to the same
    //     people. Without it, MANAGE_ROLES in one channel was a mute button
    //     pointed at anybody, including the server owner.
    //   * `role:<id>`    — refused if that role sits at or above the actor's
    //     own position, the same test may_edit_role_definitions applies to
    //     editing the role itself. Silencing a role in a channel and editing
    //     it are the same act performed through different state.
    //   * `role:everyone` is EXEMPT from rank, and deliberately: @everyone is
    //     the floor, not a principal above anyone, and `@everyone DENY
    //     VIEW_CHANNEL` is literally how a private channel is made on this
    //     server (docs/membership-vs-visibility.md). Refusing it would refuse
    //     the feature. Containment still binds it, which is the half that
    //     matters — you cannot deny the channel a permission you do not have
    //     in it.
    //
    // Rank is NOT applied to the granting direction. Handing a senior
    // principal more access in a channel takes nothing from anyone and is
    // ordinary administration; requiring rank for it would mean a channel's
    // own manager could not let their own administrators in.
    //
    // A CONSEQUENCE WORTH NAMING: an actor whose MANAGE_ROLES comes only from
    // an override in this one channel sits at role position 0, so they may let
    // people IN to their channel but may not write a targeted DENY against
    // anybody — `outranks()` is strict and everyone is at or above 0. That is
    // the same answer the server already gives such an account for kicking,
    // banning or renaming a peer, and muting somebody in a channel is not a
    // lesser act than those.
    RoleChangeVerdict may_write_channel_override(
        const std::string& actor_id, const std::string& room_id,
        const std::string& state_key, const ChannelPermissionOverride& before,
        const ChannelPermissionOverride& proposed);

private:
    // Role data is identical for every room in a single request, but compute()
    // is called once per room — an initial sync across 50 channels re-read it
    // 100 times, all serialised behind the store's global mutex. Memoise for
    // the lifetime of this engine, which is a single request.
    const std::vector<ServerRole>& server_roles();
    const std::vector<std::string>& member_role_ids(const std::string& user_id);
    // Memoised for the same reason: a sync pass calls compute() repeatedly for
    // the same rooms, and a room does not change kind mid-request.
    bool is_direct_room(const std::string& room_id);
    // Every room carrying a bsfchat.channel.permissions event — the only rooms
    // channel_access_excess() has to look at, for the reason given above its
    // declaration. Memoised like the rest: one request can ask about rank more
    // than once (a role-document write tests every role in the document), and
    // the answer cannot change under it, because an engine lives for exactly
    // one request.
    const std::vector<std::string>& override_rooms();

    SqliteStore& store_;
    const Config& config_;

    std::optional<std::vector<ServerRole>> server_roles_cache_;
    std::unordered_map<std::string, std::vector<std::string>> member_roles_cache_;
    std::unordered_map<std::string, bool> direct_room_cache_;
    std::optional<std::vector<std::string>> override_rooms_cache_;
};

} // namespace bsfchat
