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

    // Returns the highest role position the user holds. Used for hierarchy
    // checks like "mods can't modify admins." @everyone is position 0.
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
    RoleChangeVerdict may_edit_role_definitions(const std::string& actor_id,
                                                const std::vector<ServerRole>& proposed);

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
