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

    // Returns true if `actor` outranks `target` — i.e. actor's highest role
    // position is strictly greater than target's highest. Used to gate
    // kick/ban/role-assignment against higher-ranked users.
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

    SqliteStore& store_;
    const Config& config_;

    std::optional<std::vector<ServerRole>> server_roles_cache_;
    std::unordered_map<std::string, std::vector<std::string>> member_roles_cache_;
    std::unordered_map<std::string, bool> direct_room_cache_;
};

} // namespace bsfchat
