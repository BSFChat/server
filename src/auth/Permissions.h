#pragma once

#include <bsfchat/MatrixTypes.h>
#include <bsfchat/Permissions.h>

#include <string>

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
    SqliteStore& store_;
    const Config& config_;
};

} // namespace bsfchat
