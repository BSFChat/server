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

private:
    // Role data is identical for every room in a single request, but compute()
    // is called once per room — an initial sync across 50 channels re-read it
    // 100 times, all serialised behind the store's global mutex. Memoise for
    // the lifetime of this engine, which is a single request.
    const std::vector<ServerRole>& server_roles();
    const std::vector<std::string>& member_role_ids(const std::string& user_id);

    SqliteStore& store_;
    const Config& config_;

    std::optional<std::vector<ServerRole>> server_roles_cache_;
    std::unordered_map<std::string, std::vector<std::string>> member_roles_cache_;
};

} // namespace bsfchat
